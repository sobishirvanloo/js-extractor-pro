"""
Framework fingerprinting by code signatures.
"""
import re


_FRAMEWORK_SIGS = [
    ("React",       [r'React\.createElement', r'__SECRET_INTERNALS_DO_NOT_USE', r'react-dom']),
    ("Next.js",     [r'__NEXT_DATA__', r'next/router', r'_next/static']),
    ("Vue",         [r'Vue\.component', r'__vue_component__', r'createApp\s*\(']),
    ("Nuxt",        [r'__nuxt', r'nuxtApp', r'\$nuxt']),
    ("Angular",     [r'angular\.module', r'ng-version', r'@angular/core']),
    ("Svelte",      [r'SvelteComponent', r'__svelte', r'svelte/internal']),
    ("Ember",       [r'Ember\.Application', r'ember-source']),
    ("Backbone",    [r'Backbone\.Model', r'Backbone\.View']),
    ("jQuery",      [r'jQuery\.fn', r'\$\.ajax\s*\(']),
    ("Webpack",     [r'__webpack_require__', r'webpackChunk']),
    ("Vite",        [r'import\.meta\.hot', r'/@vite/client']),
    ("GraphQL",     [r'gql`', r'ApolloClient', r'graphql-ws']),
]



def detect_frameworks(all_js: str) -> list[str]:
    """Scan combined JS text for framework fingerprints."""
    detected = []
    for name, patterns in _FRAMEWORK_SIGS:
        if any(re.search(p, all_js) for p in patterns):
            detected.append(name)
    return detected

