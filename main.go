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

/*
Command iam_visibility_audit will enumerate all projects and organizations Workspace users may have access to outside
of their primary organizationID.

see:
 https://cloud.google.com/resource-manager/docs/access-control-org#restricting_visibility

Arguments:

	impersonatedServiceAccount = flag.String("impersonatedServiceAccount", "", "Impersonated Service Accounts the script should run as")
	organization               = flag.String("organization", "", "The organizationID that is the subject of this audit")
	subject                    = flag.String("subject", "", "The admin user to for the organization that can use the Directory API to list users")
	cx                         = flag.String("cx", "", "Workspace Customer ID number")
	serviceAccountFile         = flag.String("serviceAccountFile", "", "Servie Account JSON files with IAM permissions to the org")

	-v 10  adjust log verbosity level

Usage:

$ go run main.go --impersonatedServiceAccount=dwd-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --subject=$DOMAIN_ADMIN \
  --organization $ORGANIZATION_ID \
  -cx $CX --alsologtostderr=1 -v 10
*/
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"sync"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

const (
	maxRequestsPerSecond  float64 = 4 // "golang.org/x/time/rate" limiter to throttle operations
	burst                 int     = 1
	maxPageSize           int64   = 1000
	assetTypeOrganization string  = "cloudresourcemanager.googleapis.com/Organization"
	assetTypeProject      string  = "cloudresourcemanager.googleapis.com/Project"
)

func main() {

	serviceAccountFile := flag.String("serviceAccountFile", "", "Service Account JSON files with IAM permissions to the org")
	impersonatedServiceAccount := flag.String("impersonatedServiceAccount", "", "Impersonated Service Accounts the script should run as")
	organization := flag.String("organization", "", "The organizationID that is the subject of this audit")
	subject := flag.String("subject", "", "The admin user to for the organization that can use the Directory API to list users")
	cx := flag.String("cx", "", "Workspace Customer ID number")
	delay := flag.Int("delay", 1*1000, "delay in ms for each user iterated")

	flag.Parse()
	defer glog.Flush()
	ctx := context.Background()

	// Configure a rate limiter that will control how frequently API calls to
	// Cloud Resource Manager is made.
	limiter := rate.NewLimiter(rate.Limit(maxRequestsPerSecond), burst)

	// Initialize a randomSeed for use later
	rand.Seed(time.Now().UnixNano())

	if *organization == "" || *subject == "" || *cx == "" {
		glog.Error("--organization, --cx and --subject must be specified")
		return
	}
	if (*serviceAccountFile == "" && *impersonatedServiceAccount == "") || (*serviceAccountFile != "" && *impersonatedServiceAccount != "") {
		glog.Error("either --serviceAccountFile or --impersonatedServiceAccount must be specified")
		return
	}

	// Parse the serviceAccount names or keys provided. Multiple values can be set to shard API quota between projects.
	serviceAccounts, svcAccountKeys, err := parseServiceAccounts(*impersonatedServiceAccount, *serviceAccountFile)
	if err != nil {
		glog.Errorf("Error parsing serviceAccounts %v", err)
		return
	}

	// Select an random serviceAccount to use.
	impersonateAccount, svcKeyCred, err := getRandomServiceAccount(serviceAccounts, svcAccountKeys)
	if err != nil {
		glog.Errorf("Error finding valid serviceAccount %v", err)
		return
	}

	// Initialize the Cloud Asset API.
	// This api is used to find the projects in an ORG
	assetClient, err := getAssetClient(ctx, impersonateAccount, svcKeyCred)
	if err != nil {
		glog.Errorf("Error getting Cloud Asset API Client %v", err)
		return
	}

	// Use the Cloud Asset API to recall/find the Organization for provided organizationID.
	// We do not really need to do this section since the the orgID was provided in the input argument.
	// We are also setting a default query filter to an empty value so to return all all organizations
	//  see https://cloud.google.com/asset-inventory/docs/searching-resources#how_to_construct_a_query
	// The queryFilter does not really apply to an organization search and instead is useful in the projects search later
	// We are doing this as a type of input validation with the asset-api to search/narrow the organization.
	queryFilter := ""
	allOrganizations, err := findResourcesByAssetType(ctx, *organization, assetTypeOrganization, queryFilter, assetClient)
	if err != nil {
		glog.Errorf("Error finding Organizations %v", err)
		return
	}

	// Use the Cloud Asset API to recall/find the projects for provided organizationID.
	// We do not use the Resource Manager api here since that would return all the projects
	// the caller has access to, not just those restricted to the organization we want.
	// We are also setting a default "emptyQuery" value here to return all projects.
	// You can specify a query filter here to configure the set of projects to evaluate.
	//  eg: queryFilter = "state=ACTIVE"  will find all active projects
	// see https://cloud.google.com/asset-inventory/docs/searching-resources#how_to_construct_a_query
	queryFilter = ""
	allProjects, err := findResourcesByAssetType(ctx, *organization, assetTypeProject, queryFilter, assetClient)
	if err != nil {
		glog.Errorf("Error finding all projects in the organization %v", err)
		return
	}

	glog.V(20).Infoln("      Getting Users")

	// Initialize the Workspace Admin client
	// This client will be used to find users in a given Cloud Identity/Workspace domain
	adminService, err := getAdminServiceClient(ctx, impersonateAccount, svcKeyCred, *subject)
	if err != nil {
		glog.Errorf("Error initializing admin client %v", err)
		return
	}

	// If you want to narrow the search to a subset of users, apply a searchFilter here
	//  https://developers.google.com/admin-sdk/directory/v1/guides/search-users
	//	eg.
	//   searchFilter := "isAdmin=false"

	searchFilter := ""
	allUsers, err := findDomainUsers(ctx, *cx, searchFilter, adminService)
	if err != nil {
		glog.Errorf("Error finding domain users %v", err)
		return
	}
	glog.V(10).Infof("      Total Projects in Organization %d", len(allProjects))
	glog.V(10).Infof("      Total Users in Organization %d", len(allUsers))

	// Launch goroutines for each user and find which projects and organizations they have access to
	var wg sync.WaitGroup
	for _, u := range allUsers {

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Select a random service account to use per user and distribute quota consumption
			impersonateAccount, svcKeyCred, err := getRandomServiceAccount(serviceAccounts, svcAccountKeys)
			if err != nil {
				glog.Errorf("Error finding valid serviceAccount for user %s %v", u.PrimaryEmail, err)
				return
			}

			// Get a resource manager API client that acts as the current user
			crmService, err := getResourceManagerClient(ctx, impersonateAccount, svcKeyCred, u.PrimaryEmail)
			if err != nil {
				glog.Errorf("Error getting ResourceManager client for user %s %v", u.PrimaryEmail, err)
				return
			}

			// Find all the organizations and projects the user has access to

			// The organizationFilter can be used to limit the asset api query.
			// In almost all cases, this should be empty since we want to see all organizations visible to the user.
			// see https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v3#OrganizationsSearchCall.Query

			// Projects.Search() accepts a Filter parameter which will return a subset
			// of projects that match the specifications.
			// By default, if the Filter value is not set and all projects will be returned.
			// However, the code below leaves the parameter
			// explicitly defined in the event you want to query and evaluate on a
			// subset of projects. projectFilter="lifecycleState=ACTIVE"
			// See:
			// https://cloud.google.com/resource-manager/reference/rest/v3/organizations/search
			// see https://pkg.go.dev/google.golang.org/api@v0.58.0/cloudresourcemanager/v3#ProjectsSearchCall.Query
			organizationFilter := ""
			projectFilter := ""
			userOrganizations, err := getOrganizations(ctx, limiter, organizationFilter, *crmService, *u)
			if err != nil {
				glog.Errorf("Error finding Organizations for user %s %v", u.PrimaryEmail, err)
				// don't return, try to get the projects at least.
			}
			// We are only interested in the projectNumber (which is in the name field) and ID so restrict the response to just those fields
			// see https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
			fields := "nextPageToken,projects(name,projectId)"
			userProjects, err := getProjects(ctx, limiter, projectFilter, fields, *crmService, *u)
			if err != nil {
				glog.Errorf("Error finding Projects for user %s %v", u.PrimaryEmail, err)
				return
			}

			// Find the projects and organizations that do NOT exist in the list of projects under the subject organization.
			// The projects the user has access to that is not included in []allProjects should be outside the subject organization.
			for _, o := range userOrganizations {
				glog.V(50).Infof("             User [%s] has Organization visibility to %s", u.PrimaryEmail, o.Name)
				if _, ok := allOrganizations[o.Name]; !ok {
					glog.V(2).Infof("             User [%s] has external organization visibility to [%s](%s)", u.PrimaryEmail, o.Name, o.DisplayName)
				}
			}
			glog.V(50).Infof("             User [%s] can see %d projects", u.PrimaryEmail, len(userProjects))
			for _, p := range userProjects {
				glog.V(50).Infof("             User [%s] has Project visibility to %s", u.PrimaryEmail, p.ProjectId)
				if _, ok := allProjects[p.ProjectId]; !ok {
					glog.V(2).Infof("             User [%s] has external project visibility to [%s](%s)", u.PrimaryEmail, p.Name, p.ProjectId)
				}
			}
		}()
		time.Sleep(time.Duration(*delay) * time.Millisecond)
	}

	wg.Wait()
}

// If multiple service accounts are specified in the command line, parse each one of them
func parseServiceAccounts(impersonatedAccounts, keysFiles string) ([]string, [][]byte, error) {
	var serviceAccountPool []string
	var keyBytesPool [][]byte
	if keysFiles != "" {
		for _, k := range strings.Split(keysFiles, ",") {
			svcAccountJSONBytes, err := ioutil.ReadFile(k)
			if err != nil {
				return nil, nil, err
			}
			keyBytesPool = append(keyBytesPool, svcAccountJSONBytes)
		}
	}

	if impersonatedAccounts != "" {
		serviceAccountPool = strings.Split(impersonatedAccounts, ",")
	}

	return serviceAccountPool, keyBytesPool, nil
}

func getRandomServiceAccount(accounts []string, keys [][]byte) (string, []byte, error) {
	var selectedAccount string
	var selectedKey []byte
	if len(accounts) > 0 {
		selectedAccount = accounts[rand.Intn(len(accounts))]
		glog.V(50).Infof("             Selecting serviceAccount: %s", selectedAccount)
	}
	if len(keys) > 0 {
		keyIndex := rand.Intn(len(keys))
		selectedKey = keys[keyIndex]
		glog.V(50).Infof("             Selecting serviceAccount keyIndex value: %d", keyIndex)
	}
	// this should not happen
	if selectedAccount == "" && selectedKey == nil {
		return "", nil, fmt.Errorf("no valid service account found")
	}
	return selectedAccount, selectedKey, nil
}

func findDomainUsers(ctx context.Context, cx string, searchFilter string, adminService *admin.Service) ([]*admin.User, error) {

	allUsers := make([]*admin.User, 0)
	q := adminService.Users.List().Customer(cx).Query(searchFilter)
	err := q.Pages(ctx, func(page *admin.Users) error {
		allUsers = append(allUsers, page.Users...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return allUsers, nil
}

func findResourcesByAssetType(ctx context.Context, organizationID string, assetType string, query string, assetClient *asset.Client) (map[string]*assetpb.ResourceSearchResult, error) {

	resourceList := make(map[string]*assetpb.ResourceSearchResult)

	req := &assetpb.SearchAllResourcesRequest{
		Scope:      fmt.Sprintf("organizations/%s", organizationID),
		Query:      query,
		AssetTypes: []string{assetType},
		PageSize:   int32(maxPageSize),
	}

	it := assetClient.SearchAllResources(ctx, req)
	for {
		response, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		switch {
		case assetType == assetTypeOrganization:
			orgName := strings.TrimPrefix(response.Name, "//cloudresourcemanager.googleapis.com/organizations/")
			glog.V(20).Infof("     Found Organization %s", orgName)
			resourceList[fmt.Sprintf("organizations/%s", orgName)] = response
		case assetType == assetTypeProject:
			projectID := strings.TrimPrefix(response.Name, "//cloudresourcemanager.googleapis.com/projects/")
			glog.V(20).Infof("     Found projectID %s", projectID)
			resourceList[projectID] = response
		default:
			return nil, fmt.Errorf("error getting resources:  unknown assetType: %s", assetType)
		}
	}
	return resourceList, nil
}

func getAssetClient(ctx context.Context, impersonateAccount string, serviceAccountData []byte) (*asset.Client, error) {
	if impersonateAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: impersonateAccount,
			Scopes:          []string{cloudresourcemanager.CloudPlatformScope},
		})
		if err != nil {
			return nil, err
		}
		return asset.NewClient(ctx, option.WithTokenSource(ts))
	}
	cred, err := google.CredentialsFromJSONWithParams(ctx, serviceAccountData, google.CredentialsParams{
		Scopes: []string{cloudresourcemanager.CloudPlatformScope},
	})
	if err != nil {
		return nil, err
	}
	return asset.NewClient(ctx, option.WithCredentials(cred))

}

func getAdminServiceClient(ctx context.Context, impersonateAccount string, serviceAccountData []byte, impersonatedUser string) (*admin.Service, error) {
	if impersonateAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: impersonateAccount,
			Scopes:          []string{admin.AdminDirectoryUserReadonlyScope},
			Subject:         impersonatedUser,
		})
		if err != nil {
			return nil, err
		}
		return admin.NewService(ctx, option.WithTokenSource(ts))
	}
	cred, err := google.CredentialsFromJSONWithParams(ctx, serviceAccountData, google.CredentialsParams{
		Scopes:  []string{admin.AdminDirectoryUserReadonlyScope},
		Subject: impersonatedUser,
	})
	if err != nil {
		return nil, err
	}
	return admin.NewService(ctx, option.WithCredentials(cred))
}

func getResourceManagerClient(ctx context.Context, impersonateAccount string, serviceAccountData []byte, impersonatedUser string) (*cloudresourcemanager.Service, error) {
	if impersonateAccount != "" {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: impersonateAccount,
			Scopes:          []string{cloudresourcemanager.CloudPlatformScope}, // should only need CloudPlatformReadOnlyScope but the ResourceManager API requires full for Projects.Query() (b/203080436)
			Subject:         impersonatedUser,
		})
		if err != nil {
			return nil, err
		}
		return cloudresourcemanager.NewService(ctx, option.WithTokenSource(ts))
	}
	cred, err := google.CredentialsFromJSONWithParams(ctx, serviceAccountData, google.CredentialsParams{
		Scopes:  []string{cloudresourcemanager.CloudPlatformScope},
		Subject: impersonatedUser,
	})
	if err != nil {
		return nil, err
	}
	return cloudresourcemanager.NewService(ctx, option.WithCredentials(cred))
}

func getOrganizations(ctx context.Context, limiter *rate.Limiter, filter string, crmService cloudresourcemanager.Service, u admin.User) ([]*cloudresourcemanager.Organization, error) {
	glog.V(50).Infof("             Getting Organizations for user %s", u.PrimaryEmail)

	organizations := make([]*cloudresourcemanager.Organization, 0)
	req := crmService.Organizations.Search().Query(filter).PageSize(maxPageSize)
	err := req.Pages(ctx, func(page *cloudresourcemanager.SearchOrganizationsResponse) error {
		organizations = append(organizations, page.Organizations...)
		if err := limiter.Wait(ctx); err != nil {
			glog.Errorf("Error in rate limiter for user %s %v", u.PrimaryEmail, err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return organizations, nil
}

func getProjects(ctx context.Context, limiter *rate.Limiter, filter string, fields string, crmService cloudresourcemanager.Service, u admin.User) ([]*cloudresourcemanager.Project, error) {
	glog.V(50).Infof("             Getting Projects for user %s", u.PrimaryEmail)

	projects := make([]*cloudresourcemanager.Project, 0)
	req := crmService.Projects.Search().Query(filter).Fields(googleapi.Field(fields)).PageSize(maxPageSize)
	err := req.Pages(ctx, func(page *cloudresourcemanager.SearchProjectsResponse) error {
		projects = append(projects, page.Projects...)
		if err := limiter.Wait(ctx); err != nil {
			glog.Errorf("Error in rate limiter for user %s %v", u.PrimaryEmail, err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return projects, nil
}
