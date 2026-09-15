# AzFilesSmbMI Release Pipeline Guide

**Repository:** Azure/AzFilesSmbMIClient  
**Pipeline Location:** `pipelines/release.yml`  
**ADO Organization:** msazure  
**ADO Project:** One

---

## 1. Overview

This pipeline builds, signs, and optionally publishes the AzFilesSmbMI library. It uses OneBranch governed templates for compliance and produces:

- Signed native C++ DLL (`AzFilesSmbMI.dll`)
- Signed managed .NET DLL (`Microsoft.Azure.AzFilesSmbMI.dll`)
- Signed client EXE (`AzFilesSmbMIClient.exe`)
- Signed NuGet package (published to the **Official** feed)
- GitHub Release with signed binaries (optional, requires `release` parameter)

## 2. Prerequisites

### 2.1 GitHub Personal Access Token (PAT)

The GitHub Release step uses a PAT stored in an Azure DevOps variable group. This token **does not need to be regenerated for every run** — it persists until it expires.

> **⚠️ Security:** Never share PATs in chat, email, or code. Always store them as secret variables.

#### Creating the GitHub PAT

1. Go to **https://github.com/settings/tokens?type=beta** (Fine-grained tokens)
2. Click **Generate new token**
3. Fill in the fields:

   | Field | Value |
   |---|---|
   | Token name | `AzFilesSmbMI-Release-Pipeline` |
   | Expiration | Choose an appropriate duration (max 1 year recommended) |
   | Resource owner | `Azure` |
   | Repository access | Select **Only select repositories** → `Azure/AzFilesSmbMIClient` |

4. Under **Repository permissions**, set:

   | Permission | Access Level |
   |---|---|
   | Contents | **Read and write** |

5. Click **Generate token**
6. **Copy the token immediately** — it will not be shown again

#### Storing the PAT in Azure DevOps Variable Group

1. Go to Azure DevOps: **Pipelines** → **Library**
2. If the variable group `GitHubSecrets` already exists, click on it. Otherwise, click **+ Variable group**
3. Set **Variable group name**: `GitHubSecrets`
4. Click **+ Add** to add a variable:

   | Name | Value | Secret |
   |---|---|---|
   | `GitHubPAT` | *(paste the token)* | Click the **lock icon** to make it secret |

5. Click **Save**
6. Go to the **Pipeline permissions** tab on the variable group page
7. Click **+** and authorize your release pipeline to use this variable group

> **ℹ️ Token Renewal:** When the GitHub PAT expires, generate a new one following the steps above and update the `GitHubPAT` value in the `GitHubSecrets` variable group. No pipeline code changes are needed.

## 3. Running the Pipeline

### 3.1 Build Only (No GitHub Release)

1. Go to Azure DevOps → **Pipelines** → select the **AzFilesSmbMI** pipeline
2. Click **Run pipeline**
3. Set the parameters:

   | Parameter | Value | Description |
   |---|---|---|
   | Build Configuration to Use | `Debug` or `Release` | Select the build configuration |
   | Publish GitHub Release | **unchecked** (default) | Do not publish to GitHub |

4. Select the **Branch/tag** to build from
5. Click **Run**

### 3.2 Build + Publish GitHub Release

1. Go to Azure DevOps → **Pipelines** → select the **AzFilesSmbMI** pipeline
2. Click **Run pipeline**
3. Set the parameters:

   | Parameter | Value | Description |
   |---|---|---|
   | Build Configuration to Use | `Release` | **Must be Release** for production releases |
   | Publish GitHub Release | **checked** | Publishes signed binaries to GitHub |

4. Select the **Branch/tag** (typically `main` for production releases)
5. Click **Run**

> **ℹ️ What gets published to GitHub:** All signed binaries from the build output directory, including DLLs, LIBs, headers, and EXE files. The release is created as a **pre-release** tagged with the build number (e.g., `v1.2.03473.116`).

## 4. Pipeline Parameters Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `buildConfig` | Choice | `Debug` | Build configuration: `Debug` or `Release` |
| `release` | Boolean | `false` | When checked, publishes signed binaries to a GitHub Release |

## 5. Pipeline Stages and What They Do

| Stage | Job | Description |
|---|---|---|
| `build` | `main` | Builds C++ DLL, managed DLL, and EXE. Signs all binaries. Creates and signs NuGet package. Optionally publishes GitHub Release. |

### Build Job Steps (in order)

1. Install .NET SDK 9.x
2. Install and authenticate NuGet
3. Set build version number
4. Configure NuGet SSL settings
5. Checkout source code
6. Build native C++ DLL (`AzFilesSmbMI.vcxproj`)
7. Build managed .NET DLL (`Microsoft.Azure.AzFilesSmbMI.csproj`)
8. Build client EXE (`AzFilesSmbMIClient.csproj`)
9. Copy binaries to output directory
10. Sign binaries (EXE, DLL, LIB) using `external_distribution` profile
11. Copy signed binaries back to build directory
12. Create NuGet package with signed binaries
13. Sign NuGet package using `CP-401405` profile
14. *(If release=true)* Publish signed binaries to GitHub Release

## 6. NuGet Package Publishing

NuGet packages are published to the **Official** feed automatically when **both** conditions are met:

- Build Configuration is `Release`
- Source branch is `main`

No additional parameters are needed — this is controlled by the pipeline logic.

## 7. Troubleshooting

### 7.1 GitHub Release fails with 401 Unauthorized

- The GitHub PAT may have expired. Generate a new one and update it in the `GitHubSecrets` variable group.
- Verify the PAT has **Contents: Read and write** permission on `Azure/AzFilesSmbMIClient`.
- Verify the variable group is named exactly `GitHubSecrets` and the variable is named exactly `GitHubPAT`.

### 7.2 GitHub Release fails with "GITHUB_TOKEN environment variable is empty"

- The `GitHubSecrets` variable group is not linked or authorized for this pipeline.
- Go to **Pipelines** → **Library** → `GitHubSecrets` → **Pipeline permissions** and authorize the pipeline.

### 7.3 GitHub Release fails with 422 (tag already exists)

- A release with the same version tag already exists. This can happen if the pipeline is re-run. Either delete the existing release on GitHub or increment the version.

### 7.4 NuGet packages not publishing

- Ensure you selected `Release` configuration and are building from the `main` branch.

### 7.5 "You can't add variables for this run"

- This is expected. The pipeline uses governed templates that restrict runtime variables. All secrets are managed via the `GitHubSecrets` variable group, not runtime variables.

## 8. Key Links

| Resource | URL |
|---|---|
| GitHub Repository | https://github.com/Azure/AzFilesSmbMIClient |
| ADO Pipeline | https://dev.azure.com/msazure/One/_build |
| ADO Variable Groups (Library) | https://dev.azure.com/msazure/One/_library |
| GitHub PAT Management | https://github.com/settings/tokens?type=beta |
| GitHub Service Connection | https://dev.azure.com/msazure/One/_settings/adminservices?resourceId=c9e79771-fd89-49cd-bf15-fea8b7c43876 |
| OneBranch Pipeline Docs | https://aka.ms/obpipelines |
| 1ES PT Change Management | https://aka.ms/onebranch/changemanagement |
