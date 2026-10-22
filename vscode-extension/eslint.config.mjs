// Lint of the extension itself (dogfooding of the typescript.lint.eslint control).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    { ignores: ['.extension-build/**', 'node_modules/**', 'dist/**', 'bin/**', '.vscode-test/**', 'scripts/**', 'media/**'] },
    js.configs.recommended,
    ...tseslint.configs.recommendedTypeChecked,
    {
        languageOptions: {
            parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname }
        },
        rules: {
            // A promise nobody awaits loses its rejection: the first-start bugs came from there.
            // node:test reports the result of test() itself.
            '@typescript-eslint/no-floating-promises': ['error', { allowForKnownSafeCalls: [{ from: 'package', name: ['test', 'describe', 'it'], package: 'node:test' }] }],
            '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { arguments: false } }],
            '@typescript-eslint/no-explicit-any': 'error',
            // An empty catch must say why (a comment counts).
            'no-empty': ['error', { allowEmptyCatch: false }],
            '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
            eqeqeq: ['error', 'smart'],
            curly: ['error', 'all']
        }
    },
    // Plain JavaScript (this file, scripts) is outside tsconfig: lint it without type information.
    { files: ['**/*.js', '**/*.mjs', '**/*.cjs'], ...tseslint.configs.disableTypeChecked }
);
