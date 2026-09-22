This was what started as an in-class demo created in an effort to better understand passkey flows and what actually goes into logging into an account from both the user and admin ends, after class I kept working on it, largely vibe coded but mostly with the intention of just understanding the process rather than for the sake of actually programming. Found it very interesting because I found a bug in how Edge interacts with the Microsoft password manager depending on how the site queries the manager, which will be attached below. More than that, it was just nice to get a look at the lower-level specifics and watch the flow in real time because that's just nice to know.   





Bug: In Edge on Windows 11, a passkey login fails on the first PIN attempt whenever the site names which passkey it wants (allowCredentials). Retrying always works.

Why: Edge's Password Manager is registered twice: inside Edge, and inside Windows as a passkey plugin. The site's request decides the route:
- Empty list: Edge signs with its own picker. which works
- Named passkey: Edge hands the request to Windows, and Windows calls back into Edge's Password Manager. That round trip fails the first attempt. 

The logs confirm the two routes. Why the round trip fails is inferred, since only Microsoft's code would show it.

Issues:
- Common login patterns break: username-first login and passkeys as a second factor both name credentials, so they hit the broken route.
- Sites can't see it: the failure reports the same error as the user pressing Cancel.
- Stuck requests cascade: one hung request makes the next ones fail instantly.

Risks:
- Fallback to weaker login: users give up on passkeys and use passwords or SMS codes, which can be phished.
- Account takeover if the workaround is copied carelessly: with an empty list, any of the user's passkeys for the site gets accepted for signing. If the server doesn't check that the passkey belongs to the typed username, an attacker can log in as someone else with their own passkey. The demo checks this.
- Privacy: the empty-list picker shows every account stored for the site on that device.
- Failed safe: it never wrongly approved a login. It only blocked logins.

The demo's fix: send an empty list, then check that the chosen passkey belongs to the user. Which still reveals all other stored users.
