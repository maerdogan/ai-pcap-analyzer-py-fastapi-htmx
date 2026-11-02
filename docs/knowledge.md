# Knowledge base

Explanations come from `src/pcap_analyzer/knowledge.bin`. The app reads this file and never calls an AI model or an outside service, so the same result always gives the same text.

| File | Holds |
|---|---|
| `knowledge/topics.json` | What each result means, lines that depend on the capture, next checks and sources |
| `knowledge/catalog.json` | Issue titles, phases, warnings, headings and NetScaler reset codes |
| `knowledge/sources.json` | Standards and vendor documents the text relies on |
| `knowledge/columns.json` | Column titles of exported files |
| `knowledge/ui_extra.json` | Interface text the code builds at run time |
| `knowledge/translations/` | One table per language, from the English text to its translation |

## Change the text

1. Edit the JSON files. Every text needs English and Turkish, and a line in `knowledge/translations/` for each other language.
2. Run `python tools/build_knowledge.py`. It stops on missing text, unknown facts and missing sources.
3. Run the tests. They fail if `knowledge.bin` is older than the JSON files.

Interface text in the code uses the English text as its key, such as `_("Requests")`. The build finds these by itself and stops if a language lacks one.

To use your own file without changing the app, build it with `python tools/build_knowledge.py /path/team.bin` and set `PCAP_ANALYZER_KNOWLEDGE=/path/team.bin`.

## Lines that depend on the capture

A line with `when` appears only if all its tests hold. A fact that is missing never matches.

```json
{"when": [["near_timeout", "==", true]],
 "en": "The wait is very close to {timeout} seconds.",
 "tr": "Bekleme {timeout} saniyeye çok yakın."}
```

Tests are `==`, `!=`, `>=`, `<=`, `>`, `<`, `in`, `not in` and `has`. Facts are the columns of a request and the values made in `causes.facts`. In text, `{x:time}` prints seconds as a duration and `{x:term}` translates a word.
