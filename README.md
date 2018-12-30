```
____                        __  __            _          _           
|  _ \ __ _ _ __  ___ _ __  |  \/  | __ _  ___| |__   ___| |_ ___     ________
| |_) / _` | '_ \/ _ \ '__| | |\/| |/ _` |/ __| '_ \ / _ \ __/ _ \   /_______/
|  __/ (_| | |_)|  __/ |    | |  | | (_| | (__| | | |  __/ ||  __/   \_______\
|_|   \__,_| .__/\___|_|    |_|  |_|\__,_|\___|_| |_|\___|\__\___|   /_______/
          |_|                                                      @==|;;;;;;>
```

## About
Paper Machete (PM) orchestrates [Binary Ninja](https://binary.ninja) and [Grakn](https://grakn.ai) to aid static binary analysis for the purpose of finding bugs in software.

PM leverages the Binary Ninja MLIL SSA to extract semantic meaning about individual instructions, operations, register/variable state, and overall control flow.

PM migrates this data into Grakn - a knowledge graph that gives us the ability to define domain-specific ontologies for data and write powerful inference rules to form relationships between data we don't want to (or can't) explicitly store. [Heeh, how neat is that](https://www.youtube.com/watch?v=Hm3JodBR-vs)?

This project was released in conjunction with a DerbyCon 2017 talk titled "Aiding Static Analysis: Discovering Vulnerabilities in Binary Targets through Knowledge Graph Inferences." You can watch that talk [here](http://www.irongeek.com/i.php?page=videos/derbycon7/t116-aiding-static-analysis-discovering-vulnerabilities-in-binary-targets-through-knowledge-graph-inferences-john-toterhi).

Paper Machete's initial prototype and public codebase were developed by security researchers at the [Battelle Memorial Institute](https://www.battelle.org/government-offerings/national-security/cyber/mission-focused-tools). As this project matures, we hope that you will find it useful in your own research and consider contributing to the project.

## Why BNIL?
The BNIL suite of ILs is easy to work with, pleasantly verbose, and human-readable. At any point we can decide to leverage other levels and forms of the IL with little development effort on our part. When you add to that the ability to [lift multiple architectures](https://binary.ninja/faq/) and [write custom lifters](https://github.com/joshwatson/binaryninja-msp430), we have little reason not to use BNIL.

## Why Grakn?
Grakn's query language (Graql) is easy to learn and intuitive, which is extremely important in the early stages of this research while we're still hand-writing queries to model the patterns vulnerability researchers look for when performing static analysis.

The ability to write our own domain-specific ontologies lets us quickly experiment with new query ideas and ways of making our queries less complex. When we run into a case where we think "gee, if I just had access to the relationship between..." we can modify our ontology and inference rules to get that information.

While the end game for PM is to eliminate the need for human-written queries, the fact is we're starting from square one. Which means hand-jamming a lot queries to model the patterns human vulnerability researchers look for when bug hunting.

## Usage
PM provides a workflow for basic use. After installing and starting PM (see [Setup](https://github.com/cetfor/PaperMachete/wiki/Setup)), just follow the prompts:
```
[1] Analyze a targets/<target executable>
[2] Migrate a targets/<analysis>.json
[3] Run queries/cwe_*
[4] Grakn server stop, clean, and start
[5] Quit
```

See [queries/]() for examples. As you can imagine, there is no "silver bullet" query that will find all manifestations of a specific vulnerability class. Because of this, we've included versions for each CWE query. As we add new methods of finding the same CWE, we'll add scripts with incremented the version numbers to differentiate.