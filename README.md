## About thi branch
This branch a copy of master, modified to use Cloud NAT instead of dedicated nat instance in managed instance groups. No VM instances will be deployed with external IPs. To remote desktop into this environment, consider using [Identity-Aware Proxy TCP Forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding).

## Overview
This repository contains scripts and templates to simplify deployment of the resources described in Citrix's [Deploying Citrix Cloud XenApp and XenDesktop Service on the Google Cloud Platform](https://www.citrix.com/content/dam/citrix/en_us/documents/guide/deploying-citrix-cloud-xenapp-and-xendesktop-service-on-the-google-cloud-platform.pdf) published December 2017.

## Before you begin
You'll need a PowerShell environment with the [Google Cloud SDK](https://cloud.google.com/sdk/) installed.

## Deploying Citrix
Clone the repository and run deploy.ps1.

``` shell
.\deploy.ps1
```

Optionally, you can set the "UseMinimalResources" parameter to True, if you
prefer a "light weight" deployment.

``` shell
.\deploy.ps1 -UseMinimalResources $True
```

This flag will reduce overall resource
consumption by removing some of the formality of the original reference
architecture, namely:
- Instances will be deployed with public IPs to avoid necessity of NAT instances
- Single instances will be deployed instead of highly-available pairs for the
  following instances categories:
  - Domain Controllers
  - Cloud Connectors

With "UseMinimalResources" enabled, the deployment will consume only 8 vCPUs
during initial deployment, eventually shutting down the management instance to
maintain steady state consumption of only 6 vCPUs.  The remaining instances can be stopped and
started at will to minimize resource consumption when the environment is not in
use.

This smaller deployment footprint can be useful especially when utilizing the [Google Cloud Platform Free Tier
](https://cloud.google.com/free/) to experiment with Citrix on GCP.

If not otherwise provided, you will be prompted for three parameter values to allow the script to interact with Citrix Cloud APIs:
- CTXSecureClientID: This is the client ID of a client configured at Citrix Cloud ([cloud.com](https://cloud.com/)) > Identity and Access Management > API Access.
- CTXSecureClientSecret: This is the secret you were provided when the client ID was created.
- CTXCustomerID: This is the Customer ID identified on Citrix Cloud ([cloud.com](https://cloud.com/)) > Identity and Access Management > API Access.

The script will use gcloud defaults to initialize parameters such as region and project.

The deployment takes about 30 minutes to complete.

## Retrieving passwords

Use get-domain-admin-password.ps1 to retrieve the password associated with the domain administrator (ctx-[SUFFIX]\Administrator where [SUFFIX] is the randomly-assigned suffix associated with you deployment).

``` shell
.\get-domain-admin-password.ps1
```

You can use the domain administrator credentials to Remote Desktop to the mgmt instance.

The ctx-[SUFFIX] domain will be populated with ten sample users.  The usernames and passwords can be retrived with get-domain-users.ps1.

``` shell
.\get-domain-users.ps1
```

These ten domain users are configured with access to Notepad as a sample application through your xendesktop.net Citrix Storefront.

## Resizing
Add VDA instances by running resize.ps1 and specifying a larger number for the "Workers" parameter.

``` shell
.\resize.ps1 -Workers 3
```

## Cleaning up
Remove billable GCP resources with cleanup.ps1.

``` shell
.\cleanup.ps1
```

## Sample Apps

Sample apps are included to highglight how these scripts can be
extended to install custom applications. Instead of Notepad, as described in the
deployment guide, a variety of applications ([Google Chrome](https://www.google.com/chrome/), 
[LibreOffice](https://www.libreoffice.org/), [Gimp](https://www.gimp.org/), 
and [Slicer](https://www.slicer.org/)) will be installed and configured as Virtual Apps.

To configure your own sample apps, check out the following files:
- bootstrap/install-apps.ps1
- bootstrap/ctx-cleanup-apps.ps1
- bootstrap/ctx-setup-apps.ps1

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md).

## License
Copyright 2018, Google, Inc.

Licensed under the Apache License, Version 2.0

See [LICENSE](LICENSE).

