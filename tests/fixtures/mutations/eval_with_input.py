# Mutation fixture: eval() with user input.
# Expected detection: RISK-EVALEXEC.


def parse_expression(user_input: str):
    return eval(user_input)
