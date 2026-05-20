# True positive: pickle.loads on attacker-controlled data is an RCE primitive.
import pickle


def deserialize(blob: bytes):
    return pickle.loads(blob)
