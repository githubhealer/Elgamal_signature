# Project Setup and Run Guide

This file is a separate run guide for the ElGamal Digital Signature project.

> **`py` vs `python` — Note:**
> All commands in this guide use `py` (the Python Launcher for Windows).
> On most systems you can replace `py` with `python` and it will work identically.
> This project uses `py` specifically because **MINGW** is installed on the development machine,
> which causes the `python` command in PATH to point to MINGW's Python instead of the system Python.
> If you do not have MINGW, `python elgamal_gui.py` and `python elgamal_graph.py` will work fine.

## 1. Required Software Installations

Install the following software before running the project:

- Python 3.10 or newer
- pip (Python package installer)
- Tkinter (usually included with standard Python on Windows)

Install required Python libraries:

```powershell
py -m pip install sympy matplotlib
```

Optional but recommended (virtual environment):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install sympy matplotlib
```

## 2. Step-by-Step Execution Process

1. Open PowerShell in the project folder.
2. Move to the project directory:

```powershell
cd "D:\6th sem\Cryptography\REVIEW 2"
```

3. (Optional) Activate virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Ensure dependencies are installed:

```powershell
py -m pip install sympy matplotlib
```

5. Run the GUI application:

```powershell
py elgamal_gui.py
```

6. In the application, execute in order:
- Click Generate Keys
- Click Run Attack (Bad k)
- Click Apply Prevention
- Click Show Graphs

## 3. Extra Graphs — Run elgamal_graph.py

To obtain **4 additional detailed graphs** (saved as PNG files), run the graph script separately in the terminal:

```powershell
py elgamal_graph.py
```

This script runs independently of the GUI. It will:
- Generate a fresh random safe-prime parameter set (Q, P, G)
- Prompt you for the number of test cases (default 25)
- Run the full attack phase (BROKEN bad-k + REUSED-k forgery)
- Run the prevention phase (gcd check + unique k enforced)
- Display and save all 4 graphs as PNG files in the project folder

### Graphs produced

| File | Description |
|---|---|
| `graph1_outcomes.png` | Outcome per test case (BROKEN / FORGED / SECURE) |
| `graph2_gcd_values.png` | gcd(k, Q) value for each k — shows which values break the signature |
| `graph3_summary.png` | Pie chart of outcome distribution + Before vs After secure rate bar chart |
| `graph4_cumulative.png` | Cumulative attack success rate across all test cases |

> **Note:** Each run of `elgamal_graph.py` generates new random parameters (Q, P, G), so graph values will differ from the GUI run.

## 4. Instructions to Run the Project

### Main Run Command

```powershell
py elgamal_gui.py
```

### What the project does when running

- Generates ElGamal keys
- Demonstrates vulnerable behavior in the before-fix phase
- Executes reused-k attack and shows attack logs
- Applies safe-signing prevention strategy
- Displays analytics graphs comparing before and after behavior

### If you get common errors

Import error for sympy:

```powershell
py -m pip install sympy
```

Import error for matplotlib:

```powershell
py -m pip install matplotlib
```

Tkinter not found:
- Reinstall Python from python.org and make sure Tcl/Tk and IDLE/Tkinter are included.

### Stop the application

- Close the GUI window, or press Ctrl+C in terminal if needed.
