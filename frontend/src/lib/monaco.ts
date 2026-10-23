// Point @monaco-editor/react at the locally bundled monaco-editor instead of its default
// jsdelivr CDN loader: production CSP is `script-src 'self'`, and we already ship monaco-editor
// (vendor-editor chunk). YAML has no language service, so the generic editor worker is enough.
import { loader } from "@monaco-editor/react";
import * as monaco from "monaco-editor";
import EditorWorker from "monaco-editor/editor/editor.worker.js?worker";

self.MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

loader.config({ monaco });
