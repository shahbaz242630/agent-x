// ADR-005 §4, SEC-TEN-06: withTenant sets the tenant (the `app.org_id`
// setting) for one transaction only. A setting made for the whole session
// would stay on the connection and reach whoever uses that pooled connection
// next: the tenant, or any other setting (a search_path, a statement_timeout).
// So product code outside withTenant's own file may not, in any string or
// template text:
// - name the tenant setting, however it is spaced or quoted;
// - call set_config, which could build the name from pieces
//   (`'app.' || 'org_id'`);
// - start a statement with a SET that lasts for the session. SET LOCAL (and
//   SET TRANSACTION or SET CONSTRAINTS), which end with the transaction, are
//   fine. Only a statement that starts the text, or follows a `;`, counts, so
//   an UPDATE's SET and ordinary sentences are left alone.
// SQL comments are removed first, since Postgres reads a comment as a space.
// This catches SQL written out; SQL built at run time can still evade it,
// which is why every connection is also checked for a tenant when it is opened
// and each time it is taken from the pool (tenantCheckedPool).
const SETTING = /\bapp"?\s*\.\s*"?org_id\b/i;
const SET_CONFIG = /\bset_config\s*\(/i;
const NAME = '(?:"[^"]*"|[a-z_][\\w$]*)';
// `SET [SESSION] name = | TO …` or `SET [SESSION] TIME ZONE …`. SET LOCAL,
// SET TRANSACTION and SET CONSTRAINTS don't have that shape (another word
// follows SET), so they don't match.
const SET_FOR_THE_SESSION = new RegExp(
  `(?:^|;)\\s*set\\s+(?:session\\s+)?(?:time\\s+zone\\b|${NAME}(?:\\s*\\.\\s*${NAME})*\\s*(?:=|to\\b))`,
  'i',
);

/** The text with SQL comments replaced by spaces. Nested block comments aren't handled; they don't occur in our SQL. */
const withoutComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');

/** @type {import('eslint').Rule.RuleModule} */
export default {
  meta: {
    type: 'problem',
    docs: { description: 'Only withTenant names or sets the tenant setting (ADR-005 §4)' },
    schema: [],
    messages: {
      named:
        'ADR-005: only withTenant in @agentx/platform/db sets the tenant, for one transaction. Use withTenant rather than naming app.org_id.',
      setting:
        'ADR-005: product code does not call set_config or SET a setting for the whole session; a setting left on a pooled connection reaches its next user. Use SET LOCAL inside a transaction. The tenant is set only by withTenant.',
    },
  },
  create(context) {
    const check = (node, text) => {
      const sql = withoutComments(text);
      if (SETTING.test(sql)) context.report({ node, messageId: 'named' });
      else if (SET_CONFIG.test(sql) || SET_FOR_THE_SESSION.test(sql)) context.report({ node, messageId: 'setting' });
    };
    return {
      Literal(node) {
        if (typeof node.value === 'string') check(node, node.value);
      },
      TemplateElement(node) {
        check(node, node.value.cooked ?? node.value.raw);
      },
    };
  },
};
