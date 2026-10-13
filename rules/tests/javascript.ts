// Preflyt-owned detection fixtures. SPDX-License-Identifier: MIT
import * as child from "node:child_process"
declare const input: string, db: any, document: any, element: any
declare function createDecipheriv(...args: any[]): any
// ruleid: preflyt-js-eval
eval(input)
// ruleid: preflyt-js-function-constructor
new Function(input)
// ruleid: preflyt-js-tls-verification-disabled
const tls = { rejectUnauthorized: false }
// ruleid: preflyt-js-gcm-tag-length
createDecipheriv("aes-256-gcm", input, input)
// ruleid: preflyt-js-weak-random
const secretToken = Math.random()
// ruleid: preflyt-js-http-url-credentials
const url = "https://user:dummy@localhost/"
// ruleid: preflyt-js-sql-interpolation
db.query("SELECT * FROM users WHERE id=" + input)
// ruleid: preflyt-js-document-write
document.write(input)
// ruleid: preflyt-js-html-assignment
element.innerHTML = input
// ruleid: preflyt-js-child-process-shell
child.exec(input)
// ok: preflyt-js-tls-verification-disabled
const safeTls = { rejectUnauthorized: true }
// ok: preflyt-js-gcm-tag-length
createDecipheriv("aes-256-gcm", input, input, { authTagLength: 16 })
// ok: preflyt-js-sql-interpolation
db.query("SELECT * FROM users WHERE id=$1", [input])
// ok: preflyt-js-html-assignment
element.textContent = input
// ok: preflyt-js-child-process-shell
child.execFile("tool", [input])
