// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

/*

Enumerate all projects and organizations Workspace users may have access to outside
of their primary organizationID.

see:
 https://cloud.google.com/resource-manager/docs/access-control-org#restricting_visibility

Arguments:

	impersonatedServiceAccount = flag.String("impersonatedServiceAccount", "", "Impersonated Service Account the script should run as")
	organization               = flag.String("organization", "", "The organizationID that is the subject of this audit")
	subject                    = flag.String("subject", "", "The admin user to for the organization that can use the Directory API to list users")
	cx                         = flag.String("cx", "", "Workspace Customer ID number")
	serviceAccountFile         = flag.String("serviceAccountFile", "", "Servie Account JSON file with IAM permissions to the org")

	-v 10  adjust log verbosity level

Usage:

$ go run main.go --impersonatedServiceAccount=dwd-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --subject=$DOMAIN_ADMIN \
  --organization $ORGANIZATION_ID \
  -cx $CX --alsologtostderr=1 -v 10
*/

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

var (
	wg sync.WaitGroup

	serviceAccountFile         = flag.String("serviceAccountFile", "", "Servie Account JSON file with IAM permissions to the org")
	impersonatedServiceAccount = flag.String("impersonatedServiceAccount", "", "Impersonated Service Account the script should run as")
	organization               = flag.String("organization", "", "The organizationID that is the subject of this audit")
	subject                    = flag.String("subject", "", "The admin user to for the organization that can use the Directory API to list users")
	cx                         = flag.String("cx", "", "Workspace Customer ID number")
	delay                      = flag.Int("delay", 2*1000, "delay in ms for each user iterated")
	allProjects                = make(map[string]*assetpb.ResourceSearchResult)
	allOrganizations           = make(map[string]*assetpb.ResourceSearchResult)
	limiter                    *rate.Limiter
	svcAccountJSONBytes        []byte
)

const (
	maxRequestsPerSecond float64 = 3 // "golang.org/x/time/rate" limiter to throttle operations
	burst                int     = 1
	maxPageSize          int64   = 1000
)

func getOrganizations(ctx context.Context, u admin.User) ([]*cloudresourcemanager.Organization, error) {
	glog.V(50).Infof("             Getting Organizations for user %s", u.PrimaryEmail)
	defer wg.Done()

	var crmService *cloudresourcemanager.Service

	if *impersonatedServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: *impersonatedServiceAccount,
			Scopes:          []string{cloudresourcemanager.CloudPlatformReadOnlyScope},
			Subject:         u.PrimaryEmail,
		})
		if err != nil {
			glog.Errorf("Error creating CRM credentials for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Organization{}, err
		}
		crmService, err = cloudresourcemanager.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			glog.Errorf("Error creating CRM Service for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Organization{}, err
		}
	} else {
		cred, err := google.CredentialsFromJSONWithParams(ctx, svcAccountJSONBytes, google.CredentialsParams{
			Scopes:  []string{cloudresourcemanager.CloudPlatformReadOnlyScope},
			Subject: u.PrimaryEmail,
		})
		if err != nil {
			glog.Errorf("Error creating CRM credentials for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Organization{}, err
		}
		crmService, err = cloudresourcemanager.NewService(ctx, option.WithCredentials(cred))
		if err != nil {
			glog.Errorf("Error creating CRM Service for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Organization{}, err
		}
	}

	organizations := make([]*cloudresourcemanager.Organization, 0)

	// do not apply a  filter here; we need to audit all projects
	//  https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v1#SearchOrganizationsRequest
	noFilter := ""

	req := crmService.Organizations.Search(&cloudresourcemanager.SearchOrganizationsRequest{Filter: noFilter, PageSize: maxPageSize})

	if err := req.Pages(ctx, func(page *cloudresourcemanager.SearchOrganizationsResponse) error {
		organizations = append(organizations, page.Organizations...)
		if err := limiter.Wait(ctx); err != nil {
			glog.Fatalf("Error in rate limiter for user %s %v", u.PrimaryEmail, err)
			return err
		}
		if ctx.Err() != nil {
			glog.Fatalf("Error in rate limiter for user %s %v", u.PrimaryEmail, ctx.Err())
			return ctx.Err()
		}
		return nil
	}); err != nil {
		glog.Errorf("Error iterating visible organizations for user %s %v", u.PrimaryEmail, err)
		return []*cloudresourcemanager.Organization{}, err
	}

	for _, o := range organizations {
		glog.V(50).Infof("             User %s has Organiation visibility to %s", u.PrimaryEmail, o.Name)
		if _, ok := allOrganizations[o.Name]; !ok {
			glog.V(2).Infof("             User [%s] has external organization visibility to [%s](%s)", u.PrimaryEmail, o.Name, o.DisplayName)
		}
	}
	return organizations, nil
}

func getProjects(ctx context.Context, u admin.User) ([]*cloudresourcemanager.Project, error) {
	glog.V(50).Infof("             Getting Projects for user %s", u.PrimaryEmail)
	defer wg.Done()

	var crmService *cloudresourcemanager.Service

	if *impersonatedServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: *impersonatedServiceAccount,
			Scopes:          []string{cloudresourcemanager.CloudPlatformReadOnlyScope},
			Subject:         u.PrimaryEmail,
		})
		if err != nil {
			glog.Errorf("Error creating CRM credentials for user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Project{}, err
		}
		crmService, err = cloudresourcemanager.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			glog.Errorf("Error creating CRM Service for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Project{}, err
		}
	} else {
		cred, err := google.CredentialsFromJSONWithParams(ctx, svcAccountJSONBytes, google.CredentialsParams{
			Scopes:  []string{cloudresourcemanager.CloudPlatformReadOnlyScope},
			Subject: u.PrimaryEmail,
		})
		if err != nil {
			glog.Errorf("Error creating CRM credentials for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Project{}, err
		}
		crmService, err = cloudresourcemanager.NewService(ctx, option.WithCredentials(cred))
		if err != nil {
			glog.Errorf("Error creating CRM Service for  user %s,  %v", u.PrimaryEmail, err)
			return []*cloudresourcemanager.Project{}, err
		}
	}

	projects := make([]*cloudresourcemanager.Project, 0)
	// do not apply a list filter here; we need to audit all projects
	//  https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v1#ProjectsListCall.Filter
	noFilter := ""

	req := crmService.Projects.List().Filter(noFilter).PageSize(maxPageSize)
	if err := req.Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		projects = append(projects, page.Projects...)
		if err := limiter.Wait(ctx); err != nil {
			glog.Errorf("Error in rate limiter for user %s %v", u.PrimaryEmail, err)
			return err
		}
		if ctx.Err() != nil {
			glog.Errorf("Error in rate limiter for user %s %v", u.PrimaryEmail, ctx.Err())
			return ctx.Err()
		}
		return nil
	}); err != nil {
		glog.Errorf("Error iterating visible projects for user %s %v", u.PrimaryEmail, err)
		return []*cloudresourcemanager.Project{}, err
	}

	for _, p := range projects {
		glog.V(50).Infof("             User %s has Project visibility to %s", u.PrimaryEmail, p.ProjectId)
		if _, ok := allProjects[p.ProjectId]; !ok {
			glog.V(2).Infof("             User [%s] has external project visibility to [projects/%d](%s)", u.PrimaryEmail, p.ProjectNumber, p.ProjectId)
		}
	}
	return projects, nil
}

func main() {

	flag.Parse()
	defer glog.Flush()
	ctx := context.Background()

	// configure API rate limits
	limiter = rate.NewLimiter(rate.Limit(maxRequestsPerSecond), burst)
	if *organization == "" || *subject == "" || *cx == "" {
		glog.Error("--organization and --cx and --subject   must be specified")
		return
	}
	if (*serviceAccountFile == "" && *impersonatedServiceAccount == "") || (*serviceAccountFile != "" && *impersonatedServiceAccount != "") {
		glog.Error("either --serviceAccountFile or --impersonatedServiceAccount must be specified")
		return
	}

	if *serviceAccountFile != "" {
		var err error
		svcAccountJSONBytes, err = ioutil.ReadFile(*serviceAccountFile)
		if err != nil {
			glog.Fatal(err)
		}
	}

	// now initialize the Cloud Asset API
	//  this api is used to find the projects in an ORG
	var assetClient *asset.Client
	if *impersonatedServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: *impersonatedServiceAccount,
			Scopes:          []string{cloudresourcemanager.CloudPlatformScope},
		})
		if err != nil {
			glog.Fatal(err)
		}
		assetClient, err = asset.NewClient(ctx, option.WithTokenSource(ts))
		if err != nil {
			glog.Fatal(err)
		}
	} else {
		cred, err := google.CredentialsFromJSONWithParams(ctx, svcAccountJSONBytes, google.CredentialsParams{
			Scopes: []string{cloudresourcemanager.CloudPlatformScope},
		})
		if err != nil {
			glog.Fatal(err)
		}
		assetClient, err = asset.NewClient(ctx, option.WithCredentials(cred))
		if err != nil {
			glog.Fatal(err)
		}
	}

	// use asset-api API to recall/find the Organization for provided organizationID.  We don't really need to do this section
	//  since the the orgID was provided in the input argument.
	//  Were doing this as a type of input validation with the asset-api to search/narrow the organization.
	//  the resource-manager would also work https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v1#OrganizationsGetCall
	assetType := "cloudresourcemanager.googleapis.com/Organization"
	req := &assetpb.SearchAllResourcesRequest{
		Scope:      fmt.Sprintf("organizations/%s", *organization),
		AssetTypes: []string{assetType},
	}

	it := assetClient.SearchAllResources(ctx, req)

	for {
		response, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			glog.Fatal(err)
		}
		orgName := strings.TrimPrefix(response.Name, "//cloudresourcemanager.googleapis.com/organizations/")
		glog.V(20).Infof("     Found Organization %s", orgName)
		allOrganizations[fmt.Sprintf("organizations/%s", orgName)] = response
	}

	// use asset-ap API to recall/find the projects under the provided organizationID.
	//  we do not use the resource manager api here since that would return all the projects
	//   the caller has access to, not just restricted to the organization we want.
	//    https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v1#ProjectsListCall
	// emptyQuery: search all projects https://cloud.google.com/asset-inventory/docs/searching-resources#how_to_construct_a_query
	emptyQuery := ""
	assetType = "cloudresourcemanager.googleapis.com/Project"
	req = &assetpb.SearchAllResourcesRequest{
		Scope:      fmt.Sprintf("organizations/%s", *organization),
		Query:      emptyQuery,
		AssetTypes: []string{assetType},
	}

	it = assetClient.SearchAllResources(ctx, req)

	for {
		response, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			glog.Fatal(err)
		}
		projectID := strings.TrimPrefix(response.Name, "//cloudresourcemanager.googleapis.com/projects/")
		glog.V(20).Infof("     Found projectID %s", projectID)
		allProjects[projectID] = response
	}

	glog.V(20).Infoln("      Getting Users")

	// initialize the Workspace admin client first
	//  this client will be used to find users in a domain
	var adminService *admin.Service
	if *impersonatedServiceAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: *impersonatedServiceAccount,
			Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
			Subject:         *subject,
		})
		if err != nil {
			glog.Fatal(err)
		}
		adminService, err = admin.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			glog.Fatal(err)
		}
	} else {
		cred, err := google.CredentialsFromJSONWithParams(ctx, svcAccountJSONBytes, google.CredentialsParams{
			Scopes:  []string{admin.AdminDirectoryUserReadonlyScope},
			Subject: *subject,
		})
		if err != nil {
			glog.Fatal(err)
		}
		adminService, err = admin.NewService(ctx, option.WithCredentials(cred))
		if err != nil {
			glog.Fatal(err)
		}
	}
	// if you want to narrow the search to a subset of users, apply a filter
	//  https://developers.google.com/admin-sdk/directory/v1/guides/search-users
	//	searchFilter := "isAdmin=false"

	// for now, look for all users
	searchFilter := ""

	pageToken := ""
	q := adminService.Users.List().Customer(*cx).Query(searchFilter)
	for {
		if pageToken != "" {
			q = q.PageToken(pageToken)
		}
		r, err := q.Do()
		if err != nil {
			glog.Fatal(err)
		}
		for _, u := range r.Users {
			glog.V(20).Infof("      Found User: %s", u.PrimaryEmail)
			// just use goroutines to print out the visibility
			//  (do nothing with the returned arrays)
			wg.Add(1)
			go getOrganizations(ctx, *u)
			wg.Add(1)
			go getProjects(ctx, *u)
			time.Sleep(time.Duration(*delay) * time.Millisecond)
		}
		pageToken = r.NextPageToken
		if pageToken == "" {
			break
		}
	}
	wg.Wait()
}
