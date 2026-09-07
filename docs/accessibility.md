# Accessibility review — WCAG 2.2 AA

Reviewed 7 September 2026. Scope: every FallBCK-owned HTML view, its empty and
populated states, configuration dialogs, one-time credentials, validation,
sign-in and load/missing-record errors. Reference: [W3C WCAG 2.2 quick reference](https://www.w3.org/WAI/WCAG22/quickref/).

This is an engineering review with browser and regression-test evidence, not an
independent conformance certification. The separately embedded Temporal UI and
an organization's external identity provider are separate applications; this
review covers their links and the FallBCK sign-in boundary, not their internal
screens. Browser accessibility-tree inspection was used; a full VoiceOver/NVDA
user study and OS forced-color testing were not performed.

## Changes

- Replaced six-pixel state markers with 20-pixel SVG symbols and larger, bordered
  text badges. Success, running, failure, paused/disabled, cancelled, pending and
  warning have different silhouettes. Color supplements readable state names.
- Strengthened control borders and focus colors. All 50 semantic text, control
  and focus color pairs pass their respective 4.5:1 or 3:1 thresholds.
- Converted typography to relative units and raised tiny metadata to at least
  12px at the default font size. Navigation and table breakpoints accommodate
  larger text. Long labels, headings and user identifiers can wrap.
- Preserved table roles and column header associations when rows become records.
  Repeated row controls include the relevant resource in their accessible name.
- Associated checkbox help with its control. Dialogs wrap keyboard focus and
  restore it on dismissal. Errors receive focus without discarding form input.
  Notifications appear in document flow, avoiding overlap with focused controls;
  network errors within a dialog are presented inside it.
- Added a live-update pause/resume control. Polling does not replace focused
  controls, open disclosures or selected text; in-flight swaps obey the same
  guard. Run completion is announced without focusing the new record.
- Added an overview section index as another way to locate pages. Missing and
  invalid runs retain document titles, headings, navigation and a recovery link.

## Browser evidence

The populated fixture contained filesystem, PostgreSQL, MySQL, MongoDB and
Kubernetes jobs; storage, agents and access records; completed filesystem and
database runs; a failed Kubernetes run; and an active Kubernetes run.

| Surface | Checks performed |
| --- | --- |
| Overview, agents, targets, jobs, Kubernetes, history, enrollment, API keys | Both themes; rendered text contrast, language, headings, landmarks, accessible control names, duplicate IDs, desktop and 320 CSS-pixel reflow |
| Four run-detail variants | Same checks; live pause/resume and focus preservation tested on active run; disclosures and scrollable record/log regions reviewed |
| All nine configuration form variants | Visible labels and help associations; hidden/disabled sections; both themes; 320 CSS-pixel layout; reachable actions; 200% text plus spacing |
| Sign-in, denied sign-in, missing SSO configuration | Rendered template fixtures: contrast, headings, control names, enlarged text and reflow |
| Empty lists, load failure, invalid run | Rendered template fixtures: headings, navigation, names, contrast and enlarged text |
| Status gallery | All 17 status labels rendered; seven principal state shapes compared independently of color |
| Keyboard flows | Skip link; menu; Tab/Shift+Tab wrapping; Escape and return focus; validation focus and input preservation; live-update pause/resume and stable focused controls |

The lowest measured text contrast in the populated-page sweep was 4.93:1 in
light mode and 6.20:1 in dark mode. Automated DOM measurements used actual
computed foreground/background colors for visible text, with decorative and
screen-reader-only content excluded. These measurements supplement source and
visual review; they are not a substitute for a general accessibility engine.

All 12 populated-page variants fit at 320 CSS pixels. A separate snapshot suite
combined 200% root text size with WCAG text-spacing values: 1.5 line height,
0.12em letter spacing, 0.16em word spacing and 2em paragraph spacing. It found
navigation clipping and table overflow, both corrected and rechecked. The final
suite had no page overflow or clipped navigation/metric labels. All nine form
variants retained a scrollable content area and visible actions.

## Criterion coverage

| WCAG 2.2 A/AA criteria | Review result / applicability |
| --- | --- |
| 1.1.1 Non-text content | Informative status has text; icons and decorative archive artwork are hidden from assistive technology; brand has a text alternative. |
| 1.2.1–1.2.5 Media | Not applicable: no audio, video or synchronized media in FallBCK-owned views. |
| 1.3.1 Relationships | Landmarks, headings, fieldsets, native labels, help references, table/header roles and definition lists reviewed and regression tested. |
| 1.3.2 Meaningful sequence | DOM order follows reading and keyboard order; responsive tables retain original row/cell order. |
| 1.3.3 Sensory characteristics | Instructions name controls; state is not conveyed only by shape, position or color. |
| 1.3.4 Orientation | No orientation lock; responsive CSS supports narrow/short viewports and scrolling. |
| 1.3.5 Input purpose | No personal-data entry fields; database accounts and agent configuration are technical identifiers. Password fields use password input semantics. Authentication is delegated to SSO. |
| 1.4.1 Use of color | State labels plus distinct shapes; required fields also have native required semantics and instructions. |
| 1.4.2 Audio control | Not applicable: no automatically playing audio. |
| 1.4.3 Contrast | Rendered text checked in both themes; semantic color-pair regression check included. |
| 1.4.4 Resize text | Relative typography; 200% root-text test across populated pages and forms. |
| 1.4.5 Images of text | All operational copy is real text; brand artwork is a logo. |
| 1.4.10 Reflow | 320 CSS-pixel checks across populated pages and all form variants; tables adapt to available width and text size. |
| 1.4.11 Non-text contrast | Control boundaries, focus and status shapes meet 3:1 against their surrounding surfaces. Decorative panel rules are not needed to identify controls. |
| 1.4.12 Text spacing | Combined spacing and enlarged-text checks; fixed clipping and overflow. |
| 1.4.13 Hover/focus content | No custom tooltips or hover-only content; essential user identity is no longer ellipsized. |
| 2.1.1 Keyboard | Native links, buttons, fields, selects and disclosures; scrollable preformatted content is focusable. |
| 2.1.2 No keyboard trap | Modal focus wraps and Escape exits; focus returns to the opener. |
| 2.1.4 Character shortcuts | Not applicable: no single-character shortcuts. |
| 2.2.1 Timing | Forms have no UI-imposed completion timer. Credential/session lifetimes are authentication security controls; SSO behavior belongs to the configured provider. |
| 2.2.2 Pause/stop/hide | Live updates can be paused; reading/interacting with the record also suspends replacement. No autoplay or moving decorative content. |
| 2.3.1 Flashes | No flashing content or animations that flash. |
| 2.4.1 Bypass blocks | Visible-on-focus skip link reaches focusable main; landmarks also expose navigation and content. |
| 2.4.2 Page titles | Unique section titles; sign-in and error documents have titles. |
| 2.4.3 Focus order | DOM order, dialog entry/wrapping/dismissal, page replacement and validation focus checked. |
| 2.4.4 Link purpose | Links have text; repeated run links include run ID; repeated actions identify the resource. |
| 2.4.5 Multiple ways | Main navigation and overview section index; detail pages are also linked from dashboard/history records. |
| 2.4.6 Headings/labels | One main heading per document, descriptive section headings, labeled controls. |
| 2.4.7 Focus visible | Visible outlines, including rail/hero surfaces and scroll regions; forms preserve the native focus indication. |
| 2.4.11 Focus not obscured | In-flow notifications, scroll margins, contained dialog scrolling and reachable footer actions. |
| 2.5.1 Gestures | No multipoint or path-based gestures. |
| 2.5.2 Pointer cancellation | Actions activate on native click/release; destructive actions use confirmation. |
| 2.5.3 Label in name | Visible action text remains in each accessible name, including row-specific labels. |
| 2.5.4 Motion actuation | Not applicable: no motion-controlled actions. |
| 2.5.7 Dragging | Not applicable: no dragging-only interaction. |
| 2.5.8 Target size | Buttons/navigation meet the 24 CSS-pixel minimum; checkbox labels expand the target; inline text links use the text exception. |
| 3.1.1 Language | English language declared on every owned document. |
| 3.1.2 Language of parts | Product copy is English; user-entered host/resource names and technical identifiers do not specify a different language. |
| 3.2.1 On focus | Focusing a control does not submit or navigate. |
| 3.2.2 On input | Selects reveal related settings without navigation or submission. |
| 3.2.3 Consistent navigation | Shared navigation ordering, labels and active-page indication. |
| 3.2.4 Consistent identification | Shared status, button, table and form components. |
| 3.2.6 Consistent help | No repeated human-contact or automated-help mechanism; field help appears consistently beside its field. |
| 3.3.1 Error identification | Native validation plus server errors identifying the invalid field; errors are text and receive focus. |
| 3.3.2 Labels/instructions | Field labels, required semantics and help; backup-engine options grouped with fieldsets. |
| 3.3.3 Error suggestions | Required, range, option and format validation provide actionable messages; entered data is preserved. |
| 3.3.4 Error prevention | Existing destructive-action confirmations retained; configuration can be reviewed/edited; job start and cancellation require confirmation. |
| 3.3.7 Redundant entry | Edit forms populate existing values; validation preserves input; unchanged secrets can be kept without re-entry. |
| 3.3.8 Accessible authentication | FallBCK offers a single SSO link without a cognitive test. The external provider must be assessed separately. |
| 4.1.2 Name/role/value | Native controls; explicit dialog, menu and pause states; labeled fields; responsive table roles; decorative SVG hidden. |
| 4.1.3 Status messages | Validation and request errors use alerts; copy and live-update controls use status announcements. |

## Repeatable checks

```sh
python3 scripts/check-contrast.py
go test ./web ./pkg/auth ./pkg/api
```

`web/accessibility_test.go` checks document/field references and semantics and
ensures the principal states have different SVG shapes. Set
`FALLBCK_A11Y_EXPORT=/tmp/fallbck-a11y` while running these tests to export actual
login, empty, error and status-gallery HTML plus assets for browser review.

Use the isolated populated stack documented in `docs/frontend.md` to repeat
keyboard, mutation and responsive checks. Keep that stack running during design
review; it contains synthetic data and is independent of the normal development
database. Recheck zoom, text spacing, focus and all themes after changing shared
layout rules or color tokens.
