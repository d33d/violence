import mutators

class ProgressiveIncreaseMutator(Mutator):
    def __init__(self):
        super(ProgressiveIncreaseMutator, self).__init__()

    def mutate(self, data, howmany=8):
        if (len(data) < howmany):
            return data

        index = random.randint(0, len(data) - howmany)
        buf = ''
        fuzzed = ''

        for addend, curr in enumerate(xrange(index, index + howmany)):
            if addend + ord(data[curr]) > 0xFF:
                addend -= 0xFF
            buf += chr(ord(data[curr]) + addend)

        fuzzed = '%s%s%s' % (data[index:], buf, data[index + howmany:])
        return fuzzed

class ProgressiveDecreaseMutator(Mutator):
    def __init__(self):
        super(ProgressiceDecreaseMutator, self).__init__()

        def mutate(self, data, howmany=8):
            if (len(data) < howmany):
                return data

            index = random.randint(0, len(data) - howmany)
            buf = ''
            fuzzed = ''

            for subtrahend, curr in enumerate(xrange(index, index - howmany)):
                if ord(data[curr]) >= subtrahend:
                    buf += chr(ord(data[curr]) - subtrahend)
                else:
                    buf += chr(subtrahend - ord(data[curr]))

            fuzzed = '%s%s%s' % (data[index:], buf, data[index + howmany:])
            return fuzzed
