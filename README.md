
Real-time process execution logging program for the Cloud Process Execution Engine (CPEE) (https://cpee.org/).
The server subscribes to CPEE's Data Stream Interface and produces XES-compatible multi-document YAML trace files without modifying the engine itself.

Developed as part of the Bachelor Thesis "Using Instance-Based Events During Process
Execution to Create Trace-Based XES Logs" at the Technical University of Munich.

---

## Core Features:

- **Event Exclusion**
- **Loop Unrolling**
- **Subprocess Integration**

---

## Repository Structure

```
log_server.py              # Logging server
run_evaluation.py          # Evaluation tool
requirements_eval.txt      # Python dependencies
testsets/                  # CPEE process model XML files
  case_01_plain.xml
  case_02_parallel.xml
  case_03_exclusive_choice.xml
  case_04_subprocess_default.xml
  case_05_subprocess_include.xml
  case_06_subprocess_exclude.xml
  case_07_subprocess_exclude_include.xml
  case_08_loop_pretest.xml
  case_09_loop_posttest.xml
  case_10_nested_loop.xml
```

---

## Requirements

Python 3.9 or higher. Install dependencies with:

```bash
pip install flask PyYAML fpdf2
```

Or using the requirements file:

```bash
pip install flask -r requirements_eval.txt
```

> `flask` is required for the logging server but not listed in `requirements_eval.txt` (which covers the evaluation tool only).

---

## Running the Logging Server

Start the server on the default port (9379):

```bash
python3 log_server.py
```

The server binds to all interfaces on port `9379`. Two directories are created automatically on startup:

- `raw_events/` — per-instance event journals (phase 1 output)
- `traces/` — final XES YAML trace files (phase 2 output)

---

## Configuring Logging Behavior (Annotations)

Each task and loop element can be annotated in the CPEE graphical interface under **Annotations → Logging Behavior**:

| Option | Applies to | Effect |
|---|---|---|
| Exclude from log | Tasks, subprocess calls | Removes all lifecycle events of this activity from the trace |
| Include nested events | Subprocess calls | Merges child subprocess events into the parent trace |
| Log per iteration | Loop elements | Generates one trace file per loop iteration |

---

## Output Format

Traces are written to the `traces/` directory as multi-document YAML files.


## Running the Evaluation

The evaluation tool compares the alternative logger's output against reference traces.

**Run:**

```bash
python3 run_evaluation.py \
  --xml path/to/reference_processmodel.xml \
  --original-logs path/to/reference_traces/ \
  --alternative-logs path/to/traces/ \
  --output-dir eval_results/
```

Results are written to `eval_results/` as:
- `evaluation_report.csv`
- `evaluation_report.pdf`
