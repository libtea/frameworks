## Interview Questions
_We conducted semi-structured expert interviews. The following questionnaire was used for our two email interviews and provides an illustration of the topics covered in the other (spoken) interviews.	In the spoken interviews, the topic order and depth of discussion concerning each topic were determined by each interviewee's responses._

1. First, could you confirm that you consent to the interview and to your answers being published anonymously?
2. Which microarchitectural attacks did you work on? (You need only comment on attacks that are already public.)

 Consider the following questions for each attack you worked on. Was it always the same for each attack? If there were differences, what were the most noticeable ones, and how did they affect your work and your experience of the project?

3. What did the initial stage of the project look like? What was your starting point: did you have an idea (and if so, what inspired it?), discover something by accident, or build on a proof of concept or some example code that someone else had made?
4. Could you describe how work progressed from there?
    * Were there identifiable stages of development?
    * Did you prototype or produce PoCs? If so, when, and how were they helpful? If not, do you think that would have been helpful, and why?
    * To what extent was work parallelized in your team? Were you all working on separate tasks for the project? If not, were you directly collaborating with somebody else on the same task, or trying different approaches to the task independently?
    * Were they any communication challenges within your team or with third parties? Were you physically colocated with all members of your team? How did you communicate ideas in-person and/or online? How useful are proofs of concept or code snippets for communicating ideas?
    * Would you say your team had any processes or workflows you followed during the project? (E.g. coding standards, Agile, pair programming...) If yes, were they helpful and why? Would a certain process/workflow you didn't use have been helpful, and why?
    * _(If in academia)_ How did the work environment and processes in the project compare to your experience in industry? Were certain aspects of your work easier or harder because of this?
5. Could you describe the software implementation involved in the project?
    * Which programming language(s), tools, and libraries did you use? Which architectures were you working on?
    * Were there any functions or features you found yourself implementing repeatedly? Have these been common to multiple attacks, or just one?
    * Would it have been feasible and/or useful to have these provided by a software library? Why / why not?
    * Did you need to implement a kernel driver, modify the kernel, or implement a custom operating system at any point? How challenging was this?
    * Were there any other major challenges with the software implementation?
    * Did you develop any software tooling within your team for your task?
    * Have you subsequently reused anything you developed in later work?
6. If the project involved vulnerability disclosure, what was your experience of the disclosure process?
7. _An optional question relating to the interviewee's specific research topics. Questions not provided to respect interviewee anonymity._
8. Finally: what do you find the most challenging aspect of attack research overall? Which tasks take the most time?

## User Study Questions
_The survey was conducted online via Microsoft Forms. We reproduce the questions in full below. Note that the library names were anonymized to the participants: library1 refers to Mastik, library2 to cacheutils, and library3 to libsc._
	
**Demographics**
1. Please state your age.
2. Please state which gender you identify as.
3. What is your course of study? (E.g. Bachelors/Masters/PhD Computer Science, Computer Engineering...)
4. Rate your knowledge of/experience in the following, prior to starting this course _(participants were provided with the options 'None', 'Some experience', and 'Substantial experience')_:
    1. Software development
    2. Low-level systems software development in C/C++
    3. Low-level systems software development in a language other than C/C++
    4. Operating systems
    5. Computer architecture
    6. CPU microarchitecture and memory
    7. Information security
    8. Microarchitectural security and side-channel attacks
5. If you have research or work experience in any of the topics in Question 4, state how many months of experience you have for each relevant topic, and whether this was academic research, industry research, or non-research work experience. If your experience was part-time, estimate how many months of full-time experience it is equivalent to.
	
 **Task 1: Introduction to Cache Attacks (Histogram)**
 
 _As this was a very short introductory task, we did not assign a specific library to each group and did not ask more comprehensive questions about the library used as for Tasks 2-4. Participants who selected 'I did not work on this task' were not asked any further questions about the task._
	
6. Did you personally work on this task? (Any share of the work above 0\% counts!)
    * Yes, and my team completed this task
    * Yes, but my team did not complete this task
    * I did not work on this task
7. Did you use one of the libraries to complete the task, and if so, which did you choose?
    * library1
    * library2
    * library3
    * We did not use any of the provided libraries
8. Now you have experience with the libraries, if you had to do this task again from scratch, would you use one of the libraries to help produce your histogram?
    * library1
    * library2
    * library3
    * I would not use any of the provided libraries
	
 **Tasks 2 to 4**
 
 _The following questions were repeated for each of Tasks 2 to 4. As before, participants who selected 'I did not work on this task' were not asked any further questions about the task. The tasks were, respectively, implementing a cache covert channel, a cache template attack, and a KASLR break with software prefetches or Data Bounce<sup id="databounce-txt">[1](#databounce-fn)</sup>._
	
9. Did you personally work on this task? (Any share of the work above 0\% counts!)
    * Yes, and my team completed this task
    * Yes, but my team did not complete this task
    * I did not work on this task
10. Please estimate how long you spent on the task in total. Provide your individual estimate if you have one; otherwise provide your entire team's estimate, but please state whether it an individual or team estimate. You can round to the nearest 0.5hr. If possible, state the time spent for a "complete" solution (i.e. the minimum necessary to complete the task) and the time spent making further improvements (e.g. to get bonus points) separately.
11. Order the following activities (with 1 at the top representing the most time spent, and 6 at the bottom the least time spent) based on how much of your personal total time spent on the task (excluding the rest of your team) you spent on each activity.
    * Understanding the task, e.g. reviewing lecture notes and doing background reading/research
    * Understanding the library, e.g. building it on your system, familiarizing yourself with its features and API, and looking at the examples.
    * Implementing code for your 'complete' solution to the task, i.e. the minimum necessary to complete the task.
    * Debugging problems with your 'complete' solution
    * Implementing code for further improvements, e.g. to get bonus points
    * Debugging problems with your further improvements
12. Which library were you asked to use for this task?
    * library1
    * library2
    * library3
13. To what extent do you agree with the following statements about the library? _A Likert scale was provided with the options 'Strongly disagree', 'Somewhat disagree', 'Neither agree nor disagree', 'Somewhat agree', and 'Strongly agree'._
    * There are a good range of high-level features (e.g. ready-to-use attack primitives like Flush+Reload)
    * There are a good range of low-level features to use building my own attack primitives (e.g. timers)
    * It was easy to understand the library at the beginning
    * Once I had familiarized myself with the library, it was easy to use
    * The function names made it clear how they should be used
    * It would be easy for me to adapt or extend the library if I needed to
    * The library was easy to build
    * I had to modify the library to get it to work on my system
    * I think this library makes it faster to implement attacks compared to developing from scratch
    * I think this library reduces the amount of debugging needed compared to developing from scratch
    * This library had bugs
    * I spent a lot of time debugging my code because I misunderstood the library functions or they didn't do what they were supposed to
    * The documentation and examples were helpful
    * The library has sufficient documentation and examples
14. Were there any things you particularly liked about using this library?
15. Were there any things you particularly disliked about using this library?
16. Was this library appropriate for the task? Why / why not? Do you think the task would have taken you more, less, or about the same time with each of the other two libraries?
17. Give an overall rating for the library _(from 1 to 5 stars)_, considering how useful it might be for other microarchitectural attacks beyond this specific task.
	
 **Libraries Comparison**
 
17. In your opinion, what were the three most useful library features? (These can be features common to all the libraries, or features found in only one or two of the libraries.)
18. If you could change something in, or add a new feature to, all of the libraries, what would that be and why? You can describe multiple changes if you wish.


<sup><b id="databounce-fn">[1]</b> _Canella, C., Genkin, D., Giner, L., Gruss, D., Lipp, M., Minkin, M., Moghimi, D., Piessens, F., Schwarz, M., Sunar, B., Van Bulck, J., and Yarom, Y. Fallout: Leaking Data on Meltdown-resistant CPUs. In CCS (2019). [↩](#databounce-txt)_</sup>

## User Study Demographics
The following tables present the demographics of our user study, as reported by participants in their answers to Questions 1-5.

|      Age    | Participants|
| ----------- | ----------- |
| 23-26       | 24          |
| 27-30       | 3           |
| 31+         | 1           |

| Level of Study | Participants |
| -------------- | ------------ |
| Bachelors      | 3            |
| Masters        | 21           |
| PhD            | 2            |
| Not disclosed  | 2            |

| Field of Study                       | Participants |
| ------------------------------------ | ------------ |
| Computer Science                     | 13           |
| Computer Engineering                 | 10           |
| Software Engineering                 | 2            |
| Not disclosed                        | 3            |

| Gender      | Participants |
| ----------- | ------------ |
| Male        | 28           | 	

| Software Development   | Participants |
| ---------------------- | ------------ |
| Some experience        | 9            |
| Substantial experience | 19           |

| Systems Programming (C/C++) | Participants |
| --------------------------- | ------------ |
| No experience               | 1            | 
| Some experience             | 11           |
| Substantial experience      | 16           |

| Systems Programming (other languages) | Participants |
| ------------------------------------- | ------------ |
| No experience                         | 10           |
| Some experience                       | 12           |
| Substantial experience                | 5            |
| Not disclosed                         | 1            |

| Operating Systems      | Participants |
| ---------------------- | ------------ |
| No experience          | 1            |
| Some experience        | 19           |
| Substantial experience | 8            |

| Computer Architecture  | Participants |
| ---------------------- | ------------ |
| Some experience        | 20           |
| Substantial experience | 8            |

| CPU Microarchitecture  | Participants |
| ---------------------- | ------------ |
| No experience          | 4            |
| Some experience        | 21           |
| Substantial experience | 3            |

| Information Security   | Participants |
| ---------------------- | ------------ |
| Some experience        | 16           |
| Substantial experience | 12           |

| Microarchitectural Security | Participants |
| --------------------------- | ------------ |
| No experience               | 10           |
| Some experience             | 17           |
| Substantial experience      | 1            |	

| Relevant Work Experience  | Participants |
| ------------------------- | ------------ |
| Research                  | 4            |
| Industry (non-research)   | 15           |
| None                      | 12           |
