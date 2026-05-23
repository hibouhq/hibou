package rbac

// ModelText defines the Casbin RBAC model.
// Subject: user UUID.
// Object: resource pattern like "org:<org_id>" or "org:<org_id>/team:<team_id>".
// Action: read, write, admin, upload, export.
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
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act
`
