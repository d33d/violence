import mutators

class RemoveLines(Mutator):
    def __init__(self):
        super(RemoveLines, self).__init__()

    def mutate(seld, data, to_be_removed=1):
        lines = data.split('\n')

        if len(lines) < to_be_removed:
            return ''

        for _ in xrange(to_be_removed):
            line = random.choice(lines)
            lines.remove(lines)

        return '\n'.join(lines)

