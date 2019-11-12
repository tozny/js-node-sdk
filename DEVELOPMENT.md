# Testing

Define the following environment variables:

- REGISTRATION_TOKEN - Should be a mobile registration token (from the Innovault Console).
- API_URL - The environment to test against. For example, 'https://api.e3db.com'.

To run tests, from this directory:

```bash
> npm test
```

# Publishing

Checkout branch

Write code

Get code reviewed and approved

Use the npm build tool to automatically update package.json to the new version

```bash
# mainline release
npm version 1.0.1
# preview release
npm version 1.0.1-alpha.1
```

Use the npm build tool to make a new commit with the updated version, create a git tag to have as a github release, and push the package to npm for consumption

```bash
npm publish
```

If doing an alpha release,

```bash
npm publish --tag=alpha
```

Push the commit and tag up to remote github repository

```bash
git push
git push --tags
```

Lastly, merge and delete the branch
