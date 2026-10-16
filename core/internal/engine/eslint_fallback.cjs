'use strict';

const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function decodeVLQ(segment) {
    const values = [];
    let shift = 0;
    let value = 0;
    for (let index = 0; index < segment.length; index += 1) {
        const digit = chars.indexOf(segment[index]);
        if (digit < 0) {
            continue;
        }
        const continued = digit & 32;
        value += (digit & 31) << shift;
        if (continued) {
            shift += 5;
            continue;
        }
        const negative = value & 1;
        value >>= 1;
        values.push(negative ? -value : value);
        value = 0;
        shift = 0;
    }
    return values;
}

function lineMap(mappings) {
    const rows = String(mappings || '').split(';');
    let originalLine = 0;
    return rows.map(row => {
        let mapped = null;
        for (const segment of row.split(',')) {
            if (!segment) {
                continue;
            }
            const values = decodeVLQ(segment);
            if (values.length > 2) {
                originalLine += values[2];
                if (mapped === null) {
                    mapped = originalLine + 1;
                }
            }
        }
        return mapped;
    });
}

function remap(node, lines) {
    if (!node || typeof node !== 'object') {
        return;
    }
    if (node.loc && node.loc.start && lines[node.loc.start.line - 1]) {
        const start = lines[node.loc.start.line - 1];
        const end = lines[node.loc.end.line - 1] || start;
        node.loc.start.line = start;
        node.loc.end.line = end;
    }
    for (const key of Object.keys(node)) {
        const child = node[key];
        if (Array.isArray(child)) {
            child.forEach(item => remap(item, lines));
        } else if (child && typeof child === 'object' && key !== 'loc') {
            remap(child, lines);
        }
    }
}

function load(name) {
    try {
        return require(name);
    } catch (error) {
        return null;
    }
}

const rules = {
    'no-debugger': 'error',
    eqeqeq: 'warn',
    'no-empty': 'warn',
    'no-redeclare': 'warn',
    'no-unused-vars': 'warn'
};

const javascript = {
    files: ['**/*.{js,mjs,cjs,jsx}'],
    languageOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        parserOptions: { ecmaFeatures: { jsx: true } }
    },
    rules
};

const config = [javascript];
const typedParser = load('@typescript-eslint/parser');
const typescript = load('typescript');
const espree = load('espree');

if (typedParser) {
    config.push({
        files: ['**/*.{ts,tsx,mts,cts}'],
        languageOptions: {
            parser: typedParser,
            ecmaVersion: 'latest',
            sourceType: 'module',
            parserOptions: { ecmaFeatures: { jsx: true } }
        },
        rules
    });
} else if (typescript && espree) {
    config.push({
        files: ['**/*.{ts,tsx,mts,cts}'],
        languageOptions: {
            parser: {
                parseForESLint(code) {
                    const out = typescript.transpileModule(code, {
                        compilerOptions: {
                            target: typescript.ScriptTarget.ESNext,
                            module: typescript.ModuleKind.ESNext,
                            jsx: typescript.JsxEmit.Preserve,
                            removeComments: false,
                            sourceMap: true
                        },
                        fileName: 'file.tsx',
                        reportDiagnostics: false
                    });
                    const ast = espree.parse(out.outputText, {
                        ecmaVersion: 'latest',
                        sourceType: 'module',
                        loc: true,
                        range: true,
                        tokens: true,
                        comment: true,
                        ecmaFeatures: { jsx: true }
                    });
                    let map = null;
                    try {
                        map = JSON.parse(out.sourceMapText || '{}');
                    } catch (error) {
                        map = null;
                    }
                    if (map && map.mappings) {
                        remap(ast, lineMap(map.mappings));
                    }
                    return { ast };
                }
            },
            ecmaVersion: 'latest',
            sourceType: 'module'
        },
        rules: {
            'no-debugger': 'error',
            eqeqeq: 'warn',
            'no-empty': 'warn'
        }
    });
}

module.exports = config;
