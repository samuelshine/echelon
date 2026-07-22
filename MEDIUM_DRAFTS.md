# Building Echelon — Field Notes from the Frontend

_A running Medium draft documenting the UX and architecture decisions behind the console for an AI security firewall._

---

## Article 1 — Designing UX for AI Security Tools: When Your Users Are Two People at Once

Most dashboards are built for one person. You imagine them, you name them, you design every pixel around their goals. The console for Echelon — an ultra-low-latency firewall that sits in the critical path between an application and its LLM — doesn't get that luxury. It has to serve two people who almost never agree on what "good UI" means.

The first is a **Product Manager**. They open the dashboard on a Monday morning and want a single, honest answer: *is our AI healthy, safe, and on-budget?* They don't want to know what a DistilBERT classifier is. They want a number that went up or down, a line that's trending the wrong way, and a cost figure they can take into a meeting. For them, density is the enemy and clarity is everything. The second is a **Security Engineer**. They arrive at 2 a.m. because an alert fired, and they want the *opposite* of clarity-through-simplification. They want the raw prompt, the exact layer that tripped, the risk score to three decimal places, and the JSON payload that proves it. Hide that behind friendly abstractions and you've built them a toy.

The temptation is to build two products. The better answer — and the thesis of this whole build — is **progressive disclosure**: one surface that opens layer by layer. The PM lives on the top layer and never has to leave it. The engineer clicks, expands, and drills until they hit raw bytes. The same "why was this blocked?" question resolves to a single sentence for one user and a full cascade trace for the other. Getting that gradient right — glanceable at the top, forensic at the bottom, with no hard wall between them — is the central UX problem of this project, and nearly every design decision downstream is really a decision about *where on that gradient* a given piece of information belongs.

There's a second, subtler constraint that shapes everything: **latency is the product**. Echelon's entire pitch is that it adds only microseconds of overhead to an LLM call. A console that feels sluggish would quietly contradict the thing it's selling. So "fast" here isn't a nice-to-have — it's brand-critical. That pushes us toward virtualized tables over paginated ones, skeletons over spinners, optimistic UI on config changes, and a hard budget on interaction latency. In the next entries I'll get concrete about the stack that lets us hit those numbers, and about the one component I'm most nervous about: a bespoke visualizer for the three-fold risk cascade that no charting library ships out of the box.

_(To be continued as the build progresses.)_
