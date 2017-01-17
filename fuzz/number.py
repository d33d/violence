import mutators

class QuotedTextualNumberMutator(Mutator):
    '''
    find numbers that are inside quotes if exists substitute with a value from
    0 to 0xFFFFFFFF
    '''
    def __init__(self):
        super(QuotedTextualNumberMutator, self).__init__()

    def _coinflip(self, probability):
        ''' return true with a probability of 1/probability '''
        return random.randint(0, probability) == 0

    def mutate(self, data, attribs=1):
        pattern = re.compile('\"\d+\"')
        fuzzed = ''
        to_be_fuzzed = []
        matched = []

        for match in pattern.finditer(data):
            matched.append(match.span())

        if len(matched) == 0 or len(attribs) == 0:
            return data

        if len(matched) < attribs:
            attribs = len(matched)

        # first choose randomly which of the matched patterns will be found
        for _ in xrange(attribs):
            target = random.choice(matched)
            to_be_fuzzed.append(target)
            matched.remove(target)

        to_be_fuzzed.reverse()
        # we start to change the matched patterns backwards
        # otherwise, the indices of to_be_fuzzed variable would need to
        # recalcuated in every iteration
        for start, end in to_be_fuzzed:
            fuzzed = '%s\"%d\"%s' % (data[:start], random.randint(0, 0xFFFFFFFF), data[end:])
            data = fuzzed

        return data
