import { cpSync, mkdirSync } from 'node:fs'
mkdirSync('dist/web', { recursive: true })
cpSync('web', 'dist/web', { recursive: true })
