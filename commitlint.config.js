module.exports = {
  extends: ['@commitlint/config-conventional'],
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
    'subject-case': [2, 'never', ['start-case', 'pascal-case']],
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
  },
};
