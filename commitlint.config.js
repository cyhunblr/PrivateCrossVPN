module.exports = {
  parserPreset: {
    parserOpts: {
      headerPattern: /^(\w+)(!)?: (.+)$/,
      headerCorrespondence: ['type', 'breaking', 'subject'],
    },
  },
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'refactor',
        'chore',
        'docs',
        'build',
        'ci',
        'perf',
        'style',
        'revert',
        'test',
      ],
    ],
    'type-case': [2, 'always', 'lowercase'],
    'scope-empty': [2, 'always'],
    'header-max-length': [2, 'always', 100],
    'subject-case': [2, 'never', ['start-case', 'pascal-case']],
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
  },
};
