package rbac

// ModelText defines the Casbin RBAC model.
// Subject: user UUID.
// Object: resource pattern like "org:<org_id>", "org:<org_id>/team:<team_id>"
// or "instance/*".
// Action: read, write, admin, upload, export, triage.
//
// The matcher uses keyMatch, NOT keyMatch2. keyMatch2 reads ":name" as a named
// parameter and rewrites it to a wildcard, so the object "org:<uuid>/*"
// compiled to the regex "^org[^/]+/.*$" — which matches EVERY org. A role held
// in one organization satisfied checks against every other organization's
// resources. keyMatch treats everything before the "*" literally, so an org
// prefix stays an org prefix. Any future matcher change must keep that
// property; TestOrgPoliciesDoNotCrossOrgs pins it.
const ModelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act
`
