#!/usr/bin/env python3
"""
Read a regular expression and returns:
 * YES if word is recognized
 * NO if word is rejected"""

from typing import Set, List
from automaton import Automaton, EPSILON, State, error, warn, RegExpReader
import sys
import pdb  # for debugging


##################

def is_deterministic(a: Automaton) -> bool:
    """
    Test if an automaton is deterministic or not
    return true if deterministic
    else return false
    """
    if EPSILON in a.alphabet:
        return False
    for state in a.statesdict.values():
        for c in state.transitions.keys():
            if len(state.transitions.get(c).keys()) > 1:
                return False
    return True


##################

def recognizes(a: Automaton, word: str) -> bool:
    """
    Test if a word is recognized by an automaton
    return true if recognized
    else return false
    """
    current_state = a.initial

    for char in word:
        if char == EPSILON:
            continue

        if char not in a.alphabet or current_state.transitions.get(char) is None:
            return False

        current_state = list(current_state.transitions.get(char))[0]

    if current_state.name in a.acceptstates:
        return True
    else:
        return False


##################

def determinise(a: Automaton):
    """
    return a determinised automaton
    """

    def add_transitions(automaton: Automaton, og_state: State, character: str, dest_state: State):
        if character == EPSILON:
            if dest_state.name in automaton.acceptstates:
                automaton.make_accept(og_state.name)
            for char in dest_state.transitions:
                for dest in dest_state.transitions.get(char).keys():
                    add_transitions(automaton, og_state, char, dest)

        elif (og_state.name, character, dest_state.name) not in a.transitions:
            a.add_transition(og_state.name, character, dest_state.name)
        return

    # remove epsilon transition
    if EPSILON in a.alphabet:
        for transition in a.transitions:
            if transition[1] == EPSILON:
                og_state_name = transition[0]
                dest_state_name = transition[2]
                og_state = a.statesdict.get(og_state_name)
                dest_state = a.statesdict.get(dest_state_name)

                add_transitions(a, og_state, EPSILON, dest_state)  # recursive function

                a.remove_transition(og_state_name, EPSILON, dest_state_name)

    # -------------------
    # function new something
    def new_sth(sth: str):
        """
        Function new states and new automaton combined
        """
        for set_of_states in new_states:
            for char in a.alphabet:
                if char == EPSILON:
                    continue
                new_set = set()
                for state_name in set_of_states:
                    state = a.statesdict.get(state_name)
                    if state.transitions.get(char) is not None:
                        for destination_state in state.transitions.get(char).keys():
                            new_set.add(destination_state.name)

                if sth == "states":
                    if new_set not in new_states and new_set != set():
                        new_states.append(new_set)

                elif sth == "automate":
                    for sos in new_states:
                        if sos.difference(new_set) == set() and new_set.difference(sos) == set():
                            new_set = sos
                            det.add_transition(str(set_of_states), char, str(new_set))
                            break

    # new states
    new_states = [{a.initial.name}]
    new_sth("states")

    # -------------------
    # new automate
    det = Automaton("det")
    new_sth("automate")

    for accept_state in a.acceptstates:
        for set_of_states in new_states:
            if accept_state in set_of_states:
                det.make_accept(str(set_of_states))

    # -------------------
    # rename states
    i = 0
    for state in det.states:
        det.rename_state(state, str(i))
        i = i + 1

    return det


##################
def nouvel_etat(a1: Automaton) -> str:
    """Trouve un nouveau nom d'état supérieur au max dans `a1`"""
    maxstate = -1
    for a in a1.states:
        try:
            maxstate = max(int(a), maxstate)
        except ValueError:
            pass  # ce n'est pas un entier, on ignore
    return str(maxstate + 1)


def kleene(a1: Automaton) -> Automaton:
    """
    Return kleene star of the automaton passed in the argument
    """
    a1star = a1.deepcopy()
    a1star.name = "a1star"
    for state in a1star.acceptstates:
        a1star.add_transition(state, EPSILON, a1star.initial.name)

    new_state_name = nouvel_etat(a1star)
    a1star.add_transition(new_state_name, EPSILON, a1star.initial.name)
    a1star.initial = a1star.statesdict[new_state_name]
    a1star.make_accept(new_state_name)

    return a1star


##################

def concat(a1: Automaton, a2: Automaton) -> Automaton:
    """
    Concatenate 2 automaton and return the result
    """
    a1a2 = a1.deepcopy()
    a1a2.name = a1.name + a2.name
    new_state_name = nouvel_etat(a1a2)
    for s in a2.states:
        if s in a1a2.states:
            while new_state_name in a2.states:
                new_state_name = str(int(new_state_name) + 1)
            a2.rename_state(s, new_state_name)
            new_state_name = str(int(new_state_name) + 1)
    for (s, a, d) in a2.transitions:
        a1a2.add_transition(s, a, d)
    a1a2.make_accept(a2.acceptstates)
    for ac in a1.acceptstates:
        a1a2.add_transition(ac, EPSILON, a2.initial.name)

    a1a2.make_accept(a1.acceptstates, accepts=False)

    return a1a2


##################

def union(a1: Automaton, a2: Automaton) -> Automaton:
    """
    Unite 2 automaton and return the result
    """
    a1ora2 = a1.deepcopy()
    a1ora2.name = a1.name + "+" + a2.name
    new_state_name = nouvel_etat(a1ora2)
    for s in a2.states:
        if s in a1ora2.states:
            while new_state_name in a2.states:
                new_state_name = str(int(new_state_name) + 1)
            a2.rename_state(s, new_state_name)
            new_state_name = str(int(new_state_name) + 1)
    for (s, a, d) in a2.transitions:
        a1ora2.add_transition(s, a, d)
    a1ora2.make_accept(a2.acceptstates)

    new_state_name = nouvel_etat(a1ora2)
    a1ora2.add_transition(new_state_name, EPSILON, a1ora2.initial.name)
    a1ora2.add_transition(new_state_name, EPSILON, a2.initial.name)
    a1ora2.initial = a1ora2.statesdict[new_state_name]

    return a1ora2


##################

def operation(l: Automaton, r: Automaton, c: str) -> Automaton:
    if c == "+":
        result = union(l, r)
        name = "union({},{})".format(l.name, r.name)
        result.name = name
    elif c == ".":
        result = concat(l, r)
        name = "concat({},{})".format(l.name, r.name)
        result.name = name
    else:
        result = kleene(r)
        name = "kleene({})".format(r.name)
        result.name = name
    return result


def regexp_to_automaton(re: str) -> Automaton:
    """
    Moore's algorithm: regular expression `re` -> non-deterministic automaton
    """
    postfix = RegExpReader(re).to_postfix()
    stack: List[Automaton] = []
    for c in postfix:
        if c in (".", "+", "*"):
            right = stack.pop()
            left = None
            if c != "*":
                left = stack.pop()
            result = operation(left, right, c)
            stack.append(result)
        else:
            automate = Automaton(c)
            automate.add_transition("0", c, "1")
            automate.make_accept("1")
            stack.append(automate)

    return stack[0]


##################

if __name__ == "__main__":

    if len(sys.argv) != 3:
        usagestring = "Usage: {} <regular-expression> <word-to-recognize>"
        error(usagestring.format(sys.argv[0]))

    regexp = sys.argv[1]
    word = sys.argv[2]

    a = regexp_to_automaton(regexp)
    a = determinise(a)
    if recognizes(a, word):
        print("YES")
    else:
        print("NO")
