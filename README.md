# Elastic Security Research

**This site has been archived**  
This site was stood up on a temporary basis as a way to provide threat research to the community.

The popularity of this research has led to the release of Elastic Security Labs.

All research and tools, previous and future, is available on the Elastic Security Labs site **https://elastic.co/security-labs**.

---

The Elastic Security Research team pairs research on emerging threats with analysis of strategic, operational, and
tactical adversary objectives.

The team produces public-facing content, in the way of summary blogs, detailed releases, and artifacts; articulating
both adversary campaign activities and threat detection steps that can be leveraged to frustrate adversary goals.

The team observes the efficacy of Malware Signatures, Behavior Protections, and Detection Rules against real-world
malware and adversary techniques.

Research priorities are chosen through open-source research vehicles, inputs from high-confidence third parties,
and data collected from Elastic's evolving telemetry.

## Workflow

The published version of the site is generated using a customized [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)
theme that uses the [Insiders](https://squidfunk.github.io/mkdocs-material/insiders/) features.

When a commit is made to the `main` branch, the custom container is used to render the Markdown content files into web
content that is then pushed to the `gh-pages` branch. Once that succeeds, GitHub Actions kicks off the action that
publishes the content to the website.


---
Contact: `threat-notification //@// elastic.co`
[Elastic Community Slack](https://elasticstack.slack.com)
