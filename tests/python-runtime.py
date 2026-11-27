#!/usr/bin/env python3
"""SDK fixture: receive from C, delegate to C, and persist the reply."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "sdk/python"))
from agent import Agent

agent = Agent()

@agent.handler("review")
def review(task):
    pathlib.Path("received").write_text(task.sender)
    task.delegate_to("sink", "review", b"+TODO\n")

@agent.handler("result")
def result(task):
    pathlib.Path("roundtrip").write_bytes(task.payload)

agent.run()
