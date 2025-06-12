# Continuous Integration

This repository's CI uses non-standard mechanisms to harmonize the usage of `dependabot` together with [`cargo vet`](https://mozilla.github.io/cargo-vet/). Since cargo-vet audits for new versions of crates are rarely immediately available once dependabots bumps the version,
the exemptions for `cargo vet` have to be regenerated for each push request opened by dependabot. To make this work, some setup is neccessary to setup the CI. The required steps are as follows:

1. Create a mew user on github. For the purpose of these instructions, we will assume that its mail address is `ci@example.com` and that its username is `ci-bot`. Protect this user account as you would any other user account that you intend to gve write permissions to. For example, setup MFA or protect the emal address of the user. Make sure to verify your e-mail.
2. Grant `ci-bot` write access to the repository.
3. Create a new personal access token for `ci-bot`. That is, in the settings for `ci-bot`, select "Developer settings" -> "Personal Access tokens" -> "Fine-grained tokens". Then click on "Generate new token". Enter a name of your choosing and choose an expiration date that you feel comfortable with. A shorter expiration period will requrie more manual management by you but is more secure than a longer one. Under "Repository permissions", grant "Read and write"-access to the "Contens" premission for the token. Grant no other permissions to the token, except for the read-only access to the "Metadata" permission, which is mandatory. Then generate the token and copy it for the next step.
4. Now, with your account that has administrative permissions for the repository, open the settings page for the repository and select "Secrets and variables" -> "Actions" and click "New repository secret". In the name field enter "CI_BOT_PAT". This name is mandatory, since it is explicitly referenced in the supply-chain workflow. Below, enter the token that was generated in the previous step.

## What this does

For the `cargo vet` check in the CI for dependabot, the `cargo vet`-exemptions have to automatically be regenerated, because otherwise this CI job will always fail for dependabot PRs. After the exemptions have been regenerated, they need to be commited and pushed to the PR. This invalidates the CI run that pushed the commit so that it does not show up in the PR anymore but does not trigger a new CI run. This is a [protection by Github](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#using-the-github_token-in-a-workflow) to prevent infinite loops. However, in this case it prevents us from having a proper CI run for dependabot PRs. The solution to this is to execute `push` operation with a personal access token.

## Preventing infinite loops

The CI is configured to avoid infinite loops by only regenerating and pushing the `cargo vet` exemptions if at least one of the following conditions is met:

- The last commit was performed by dependabot
- The last commit message ends in `--regenerate-exemptions`
