// The tags every resource with a location carries, on their own (AZ5i): the
// release's gate judges a Bicep file whole, with every file it loads, so the
// deployers, who need nothing else of names.bicep, import them from here and no
// longer read names.bicep, its app keys or the database's generation. A change
// there no longer asks for infra.ts deployers. names.bicep keeps its own copy
// until its next change (which asks every other deployment anyway) moves it
// here; infra.test.ts holds the two equal.

@export()
@description('The tags every resource with a location carries, so a stray resource stands out (policy rule `tags`).')
func resourceTags(environment string) object => {
  product: 'agent-x'
  environment: environment
  'managed-by': 'deploy/azure'
}
