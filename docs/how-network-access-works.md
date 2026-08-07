# How network access works (admin guide)

Two views of the same thing:

| Who | Page | Sees |
| --- | --- | --- |
| End user | **My Network** | Resources: *"Your browser → wiki.tdv.org:443"*, one button |
| Admin | **Zero Trust Access** → *How this works* | The real chain, and which link is broken |

Users never need to know the overlay exists. You do — so every user-facing
concept below maps to exactly one thing the platform creates for you.

---

## What the UI creates for you

Adding a resource from **Zero Trust Access → Add a resource** provisions the
whole chain. You fill in three things; the platform does the rest:

| You enter | What it becomes |
| --- | --- |
| **Name** | the service, plus its `#<name>` role attribute |
| **Target host + Port** | a `host.v1` config — where the gateway forwards |
| *(derived)* **Address people dial** | an `intercept.v1` config — what clients resolve |
| **Who can reach it** | a **Dial** policy for those identities |
| *(automatic)* | a **Bind** policy so gateways host it, and a service-edge-router policy so it is available on all gateways |

No CLI. If you prefer the raw fabric view, every object is still visible under
**Ziti Network** and in the Ziti console.

---

## Diagnosing "why can't X reach Y?"

Open **Zero Trust Access → Services → ⋯ → How this works**. It walks the chain
in the order a connection actually travels and marks the first broken link:

```
1. The resource is defined              service <name>
2. Clients know the address to dial     intercept.v1 <name>-intercept
3. The target it forwards to            host.v1 <name>-host
4. Who may reach it                     Dial policy
5. A gateway carries the traffic        Bind policy
6. A gateway is connected right now     terminator
```

Each broken step tells you what to do. Typical findings:

| Symptom | Meaning | Fix |
| --- | --- | --- |
| step 2 missing | clients cannot resolve the name | re-save the resource |
| step 4 missing | nobody is allowed to reach it | set **Who can reach it** |
| step 6 missing | no gateway is serving it | check the gateway is online and can reach the target |

This replaces `ziti edge policy-advisor` for day-to-day work.

---

## Two things that look like bugs but are not

**A resource shows "Needs setup" even though it is configured.**
Its public hostname does not resolve in DNS. The chain is fine; the *address* was
never published. Users are deliberately not given an Open button that would fail
in the browser. Publish the DNS record and it turns ready.

**The broker catalog lists systems a user has not been approved for.**
That is intentional. The catalog is org-wide; the per-user gate happens at
connect time (approval is consumed, and moderation enforced). Users see what
exists and can request access to it.

---

## Why most users never install anything

- **Web resources** are fronted for the browser, so they need no client and no
  device setup at all. This is the default path and should cover most access.
- **RDP / SSH / databases** are rendered in the browser by the session broker —
  still nothing to install.
- The desktop network client is a **fallback**, only for tools that connect
  outside the browser. Users are told this in plain words on **My Devices**.

If you are pushing the desktop client to everyone, check first whether the
resource can simply be published for the browser instead.
