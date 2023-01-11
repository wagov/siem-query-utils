#!/usr/bin/env node
"use strict";
import Fastify from 'fastify';
import { MarkdownTransformer } from '@atlaskit/editor-markdown-transformer';
import { JSONTransformer } from '@atlaskit/editor-json-transformer';
import { WikiMarkupTransformer } from '@atlaskit/editor-wikimarkup-transformer';

const transformers = {
    "md": new MarkdownTransformer(),
    "adf": new JSONTransformer(),
    "wiki": new WikiMarkupTransformer()
}

const hostname = '127.0.0.1';
const port = 3000;

const app = Fastify();

app.post("/:inputformat/to/:outputformat", async (request, reply) => {
    const { inputformat, outputformat } = request.params;
    reply.send(transformers[outputformat].encode(transformers[inputformat].parse(request.body)));
});

console.log("atlaskit-transformer listening at http://" + hostname + ":" + port);
app.listen({ port: port, hostname: hostname }, (err, address) => {
    if (err) {
        app.log.error(err);
        process.exit(1);
    }
});
