# Libtea and SCFirefox

<img src="libtea.png" width=160 alt="logo" align="left" />

This repository provides two open-source frameworks for microarchitectural attack development, **libtea** and **SCFirefox**. **libtea** provides a C header and kernel driver (compatible with Linux, Windows, and jailbroken Android) to facilitate cross-platform attack development in native code, while **SCFirefox** provides access to the functionality of **libtea** in a modified Firefox browser (or in the Spidermonkey JS Shell) to facilitate development of browser-based microarchitectural attacks. For more details and installation instructions, please see the separate READMEs for each framework.

**Publications.** These frameworks were developed at the [IAIK](https://github.com/IAIK) (Graz University of Technology) and at [Dynatrace Research](https://github.com/dynatrace-research) as part of a research project into the microarchitectural attack development process, "[Rapid Prototyping for Microarchitectural Attacks](https://www.usenix.org/conference/usenixsecurity22/presentation/easdon)", which was presented at USENIX Security 2022. They build on prior work by researchers at the IAIK and the open-source projects [PTEditor](https://github.com/misc0110/PTEditor) and [SGX-Step](https://github.com/jovanbulck/sgx-step).

```
@inproceedings {easdon2022rapid,
title = {{Rapid Prototyping for Microarchitectural Attacks}},
author = {Catherine Easdon and Michael Schwarz and Martin Schwarzl and Daniel Gruss},
booktitle = {{31st USENIX Security Symposium (USENIX Security 22)}},
year = {2022},
publisher = {{USENIX Association}}
}
```

This repository includes two appendices for the paper: the [extended bibliography](/extended-bibliography.md) for the literature review, and the [user study and interview questions](/user-study-and-interviews.md).

**License.** Both frameworks are licensed under GPLv3. Please feel free to use them and adapt them to suit your needs. Feedback and success stories are much appreciated - if the frameworks are useful for your research project, do let us know and we'll share your project here.

## Contributing
Contributions are very welcome - if you would like to contribute, please feel free to open a PR or open an issue for discussion. In particular, we'd appreciate help with the following:

* Open TODOs in the codebase
* Extending support for eviction set generation
* Extending support for AArch64 and PPC64
* Updating SCFirefox for compatibility with new releases of Firefox and SpiderMonkey