// SECURITY: Migrated from the custom Trinket marked fork
// (git+https://github.com/trinketapp/marked.git, an extended marked@0.3.2)
// to upstream marked@^4.3.0 + sanitize-html@^2.13.0.
//
// This eliminates the four HIGH advisories that previously sat as A-01
// in SECURITY.md "Accepted Operator Risk":
//   - GHSA-x5pg-88wf-qq4p (Regular Expression Denial of Service in marked)
//   - GHSA-rrrm-qjm4-v8hf (Inefficient Regular Expression Complexity)
//   - GHSA-5v2h-r2cx-5xgj (Inefficient Regular Expression Complexity)
//   - GHSA-hjcp-j389-59ff (Regular Expression Denial of Service)
//
// The fork extended marked@0.3.2 with a `sanitize: function(html)` callback
// option that drove HTML allow-listing for embedded markdown (see the
// pre-remediation `lib/shared/trinket-markdown.js:211-256`). Upstream marked
// removed the `sanitize` option entirely in marked@1.0.0, so the fork's
// behavior must be reproduced as a post-processing step. This module:
//
//   1. Registers the fork's custom code/image/link/listitem renderers via the
//      marked@4 `marked.use({ renderer: { ... } })` API (replaces the fork's
//      direct prototype mutation pattern at lines 446-464 pre-remediation).
//   2. Post-processes the rendered HTML through sanitize-html with an
//      allow-list that matches the original HTML_WHITELIST tag/attribute
//      schema, augmented with attributes required by the renderer's own
//      output (img alt/title/style/width/height; iframe class; input type/
//      checked from the listitem checkbox renderer) so markdown rendering
//      continues to work end-to-end.
//   3. Enforces the original HTML_WHITELIST.iframe.src URL pattern allow-list
//      via sanitize-html `exclusiveFilter`, which is more restrictive than
//      sanitize-html's hostname-only `allowedIframeHostnames` and faithfully
//      reproduces the fork's path-aware iframe gating (e.g. phet.colorado.edu
//      requires `/sims/`, parsons.herokuapp.com requires `/puzzle/`, etc.).
//
// Migration deviations vs. the pre-remediation fork behavior are documented
// in SECURITY.md "Migration Notes". In summary:
//   (a) sanitize-html post-processes the FULL rendered HTML, whereas the
//       fork's `sanitize` callback ran only on user-supplied raw HTML inline
//       tokens. The allow-list has therefore been widened to admit the marked
//       renderer's own emitted tags (e.g. <em>, <br>, <input>) that the fork
//       previously left untouched because they bypassed sanitize entirely.
//   (b) <img> src now accepts http/https/data, where the fork's HTML_WHITELIST
//       restricted user-typed <img> to docs.google.com/.../drawings/. The
//       restriction is widened so that markdown ![alt](url) syntax continues
//       to render. Modern browsers do not execute scripts via <img> src.
//   (c) The fork's per-attribute regex validation for the iframe `style`
//       attribute (rejecting expression / javascript / -moz-binding) is
//       reproduced via a `transformTags` callback rather than the fork's
//       inline regex, identical in semantics.

var marked       = require('marked')
  , sanitizeHtml = require('sanitize-html')
  , hljs         = require('highlight.js')
  , config       = require('config');

var browserConfig = {
  'apphostname' : config.app.url.hostname
};
var trinketConfig = {
  get : function(key) {
    return browserConfig[key];
  },
  getUrl : function(path) {
    return config.app.url.protocol + '://' + config.app.url.hostname + path;
  },
  prefix : function(path) {
  }
};

  var trinket_hosts   = [trinketConfig.get('apphostname')];
  var trinket_types   = ['python', 'html', 'music', 'glowscript', 'blocks', 'python3', 'java', 'glowscript-blocks', 'R', 'pygame'];
  var inline_trinkets = ['python', 'python3', 'html', 'glowscript', 'java', 'R', 'pygame'];

  var EMBED_URLS = [
    {
      regex : /^(?:https?\:)?\/\/(?:www\.)?youtu\.?be(?:\.com)?\/(?:watch\?v=|embed\/)?(\S+)$/i,
      attrs : 'width="420" height="315" frameborder="0" allowfullscreen',
      url   : function(match) {
        return '//www.youtube.com/embed/' + match[1];
      }
    },
    {
      regex : /^(?:https?\:)?\/\/(?:www\.)?vimeo(?:\.com)?\/(?:video\/)?(\S+)$/i,
      attrs : 'width="500" height="281" frameborder="0" webkitallowfullscreen mozallowfullscreen allowfullscreen',
      url   : function(match) {
        return '//player.vimeo.com/video/' + match[1];
      }
    },
    {
      regex : /^\/components\/viewerjs\/index\.html#/i,
      attrs : 'width="600" height="400" frameborder="0" scrolling="no" allowfullscreen mozallowfullscreen webkitallowfullscreen',
      url   : function(match) {
        return trinketConfig.getUrl(match.input);
      }
    },
    {
      regex : new RegExp(
                '^(?:https?\\:)?\\/\\/(?:www\\.)?'
                + '(' + trinket_hosts.join('|') + ')'
                + '(?:\\/embed)?\\/(' + trinket_types.join('|') + ')(.*)', 'i'
              ),
      attrs : 'class="embedded-trinket" width="100%" height="400" frameborder="0" scrolling="no"',
      url   : function(match) {
        var type = python_types.indexOf(match[2]) >= 0 ? 'python' : match[2];
        return '//' + match[1] + '/embed/' + type + match[3];
      }
    },
    {
      regex : /^(?:https?\:)?\/\/www\.slideshare\.net\/slideshow\/embed_code\//i,
      attrs : 'width="427" height="356" frameborder="0" marginwidth="0" marginheight="0" scrolling="no" style="border:1px solid #CCC; border-width:1px 1px 0; margin-bottom:5px; max-width: 100%;" allowfullscreen'
    },
    {
      regex : /^(?:https?\:)?\/\/www\.google\.com\/maps\/embed/i,
      attrs : 'width="600" height="450" frameborder="0" style="border:0"'
    },
    {
      regex : /^(?:https?\:)?\/\/phet\.colorado\.edu\/sims\//i,
      attrs : 'width="800" height="600" scrolling="no"'
    },
    {
      regex : /^(?:https?\:)?\/\/parsons\.herokuapp\.com\/puzzle\//i,
      attrs : 'width="600" height="400" frameborder="0"'
    }
  ];

  // SECURITY: Iframe src allow-list — reproduces the original
  // HTML_WHITELIST.iframe.src patterns from the marked-fork sanitize callback
  // (lib/shared/trinket-markdown.js:131-154 pre-remediation), applied via
  // sanitize-html's exclusiveFilter so iframes whose src is not on this list
  // are dropped from the output. Path-aware enforcement (e.g. phet
  // .colorado.edu requires /sims/, parsons.herokuapp.com requires /puzzle/)
  // is preserved here — sanitize-html's allowedIframeHostnames /
  // allowedIframeDomains are hostname-only and would be more permissive than
  // the fork's original guarantee.
  var IFRAME_SRC_PATTERNS = [
    /^(https?\:)?\/\/(www\.)?youtu(be\.com|\.be)\/embed\//i,
    /^(https?\:)?\/\/(www\.)?player\.vimeo\.com\/video\//i,
    /^(https?\:)?\/\/(www\.)?google\.com\/maps\/embed/i,
    /^(https?\:)?\/\/(www\.)?slideshare\.net\/slideshow\/embed_code\//i,
    /^(https?\:)?\/\/(www\.)?geogebra(tube)?\.org\//i,
    /^(https?\:)?\/\/(www\.)?pythontutor\.com\/iframe-embed\.html/i,
    /^(https?\:)?\/\/(www\.)?screencast\-o\-matic\.com\/embed/i,
    // Plotly: pattern accepts both `~user/<id>.embed` (the fork's original
    // HTML_WHITELIST regex pre-remediation lib/shared/trinket-markdown.js:139)
    // AND `~user/<id>/.embed` (the renderer-emitted format at processImage's
    // plotly path; the original renderer output bypassed the fork's sanitize
    // callback so this URL shape was never tested against the regex). The
    // optional `\/?` makes both shapes match.
    /^(https?\:)?\/\/(www\.)?plot\.ly\/\~[\w-]+\/\d+\/?\.embed/i,
    /^(https?\:)?\/\/docs\.google\.com\/.*(presentation|document|spreadsheets|forms)\//i,
    /^(https?\:)?\/\/linus\.highpoint\.edu/i,
    /^(https?\:)?\/\/physics\.highpoint\.edu/i,
    /^(https?\:)?\/\/phet\.colorado\.edu\/sims\//i,
    /^(https?\:)?\/\/parsons\.herokuapp\.com\/puzzle\//i,
    /^(https?\:)?\/\/(www\.)?loom\.com\/embed\//i,
    /^(https?\:)?\/\/forms\.office\.com\//i,
    /^(https?\:)?\/\/quizizz\.com\//i,
    /^(https?\:)?\/\/embed\.kahoot\.it\//i,
    // Trinket-host /embed/ paths (renderer emits absolute URLs after
    // trinketConfig.getUrl resolution; original HTML_WHITELIST regex
    // pre-remediation lib/shared/trinket-markdown.js:149-153)
    new RegExp(
      '^(https?\\:)?\\/\\/(www\\.)?'
      + '(' + trinket_hosts.join('|') + ')'
      + '\\/embed\\/', 'i'
    ),
    // Trinket-host /components/viewerjs/ paths — emitted by checkForEmbedUrl
    // when a markdown link/image starts with /components/viewerjs/index.html#
    // (see EMBED_URLS[2]). The fork's renderer path bypassed the sanitize
    // callback so this URL pattern was previously implicit; with sanitize-html
    // post-processing it must be added explicitly.
    new RegExp(
      '^(https?\\:)?\\/\\/(www\\.)?'
      + '(' + trinket_hosts.join('|') + ')'
      + '\\/components\\/viewerjs\\/', 'i'
    )
  ];

  function isAllowedIframeSrc(src) {
    if (!src) return false;
    for (var i = 0; i < IFRAME_SRC_PATTERNS.length; i++) {
      if (IFRAME_SRC_PATTERNS[i].test(src)) {
        return true;
      }
    }
    return false;
  }

  // SECURITY: HTML allow-list for sanitize-html post-processing — reproduces
  // the original HTML_WHITELIST tag list from the marked-fork sanitize
  // callback (pre-remediation lib/shared/trinket-markdown.js:82-156),
  // augmented with `br`, `em`, and `input` (which marked's default renderer
  // and our custom listitem renderer emit). The original `class` regex
  // (/^[a-z\-\s]+$/) is replaced by sanitize-html's standard class allow-list
  // semantics — kept names equivalent for compatibility.
  var SANITIZE_OPTIONS = {
    allowedTags: [
      // From HTML_WHITELIST (pre-remediation):
      'i', 'b', 'u', 'strong', 'blockquote', 'pre', 'code',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'sup', 'sub',
      'dd', 'dl', 'dt', 'ol', 'ul', 'li', 'strike', 'del',
      'span', 'hr', 'a', 'p', 'tr', 'td', 'th', 'thead',
      'tbody', 'tfoot', 'table', 'img', 'iframe',
      // Additionally allow tags emitted by marked's default renderer and our
      // custom listitem renderer (these were emitted-but-not-sanitized in
      // the fork because renderer output bypassed the sanitize callback):
      'br', 'em', 'input'
    ],
    allowedAttributes: {
      // class is allowed on every tag (HTML_WHITELIST.* had {class: ...})
      '*': ['class'],
      'ol': ['class', 'start', 'type'],
      'a': ['class', 'href', 'title', 'target'],
      'table': ['class', 'width'],
      // img: the fork's HTML_WHITELIST.img only allowed src restricted to
      // docs.google.com/.../drawings/. Renderer-emitted img tags carry alt,
      // title, width, height, style — so we widen the schema. See
      // SECURITY.md "Migration Notes" for the deviation rationale.
      'img': ['class', 'src', 'alt', 'title', 'width', 'height', 'style'],
      'iframe': [
        'class', 'align', 'frameborder', 'width', 'height',
        'marginwidth', 'marginheight', 'scrolling', 'seamless',
        'allowfullscreen', 'webkitallowfullscreen', 'mozallowfullscreen',
        'style', 'src', 'title'
      ],
      // input: emitted only by our custom listitem renderer for [x]/[ ]
      // checkbox markdown — never reachable from user-typed raw HTML in
      // the fork's HTML_WHITELIST, since `input` was not on the allow-list.
      'input': ['class', 'type', 'checked']
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
      // img src additionally allows data URIs — required by markdown
      // ![alt](data:...) image syntax. The fork's HTML_WHITELIST.img.src
      // would have escaped this (only docs.google drawings were allowed),
      // but the renderer path emitted ANY URL untouched. See SECURITY.md
      // "Migration Notes".
      'img': ['http', 'https', 'data']
    },
    // Allow protocol-relative URLs (//www.youtube.com/...) — the renderer
    // emits protocol-relative URLs for many embed iframes (see EMBED_URLS).
    allowProtocolRelative: true,
    // SECURITY: reproduce the fork's per-attribute regex validation for the
    // iframe `style` attribute. Original regex (pre-remediation
    // lib/shared/trinket-markdown.js:130):
    //   style: /^(.(?!expression|javascript|\-moz\-binding))*$/i
    // Equivalent here: drop the style attribute if it contains any of the
    // three dangerous tokens. Applied to img as well for parity.
    transformTags: {
      'iframe': function(tagName, attribs) {
        if (attribs.style && /(expression|javascript|-moz-binding)/i.test(attribs.style)) {
          delete attribs.style;
        }
        return { tagName: tagName, attribs: attribs };
      },
      'img': function(tagName, attribs) {
        if (attribs.style && /(expression|javascript|-moz-binding)/i.test(attribs.style)) {
          delete attribs.style;
        }
        return { tagName: tagName, attribs: attribs };
      }
    },
    // SECURITY: enforce iframe src URL pattern allow-list. sanitize-html's
    // built-in allowedIframeHostnames / allowedIframeDomains validate only
    // the hostname; the fork's original HTML_WHITELIST.iframe.src enforced
    // both hostname AND path (e.g. phet.colorado.edu/sims/, not arbitrary
    // *.colorado.edu paths). exclusiveFilter is invoked with each frame and
    // the iframe is dropped when it returns true.
    exclusiveFilter: function(frame) {
      if (frame.tag === 'iframe') {
        return !isAllowedIframeSrc(frame.attribs.src);
      }
      return false;
    }
  };

  var IPYNB_REGEXP = /\.ipynb$/i;

  // -------------------------------------------------------------------------
  // Custom marked renderers — preserve the fork's processCode / processImage
  // / processLink / listitem behavior verbatim. Registered via the marked@4
  // `marked.use({ renderer: { ... } })` API instead of the fork's direct
  // `marked.Renderer.prototype.<method> = ...` mutation. Returning `false`
  // from a custom renderer in marked@4 falls back to the default renderer
  // (used for default code/image/link rendering when our specialized paths
  // are not relevant).
  // -------------------------------------------------------------------------

  function processCode(code, lang, escaped) {

    var output = code,
        parts  = /^([a-zA-Z0-9]+)\.((?:run|trinket|console))(?:\:(.*))?$/.exec(lang),
        attrs  = {
          width  : '100%',
          height : '400'
        },
        attrStr = '',
        url, arg;

    // if it matched the regex make sure it is an inline-able trinket
    if (parts && inline_trinkets.indexOf(parts[1]) == -1) {
      parts = undefined;
    }

    if (parts) {
      if (parts[3]) {
        // accept arguments of the style x=y,x="y",x='y'
        while (arg = /(\w+)=([^,]+)/.exec(parts[3])) {
          attrs[arg[1]] = arg[2].replace(/^("|')|("|')$/g, '');
          parts[3]      = parts[3].substr(arg[0].length);
        }
      }

      url = trinketConfig.getUrl('/embed/' + parts[1]);
      if (attrs.autorun !== "false") {
        url = url + '?start=result';
      }

      if (parts[1] === 'python' && parts[2] === 'console') {
        url = url + '&runMode=console&outputOnly=true&runOption=console&leftMenu=true';
        code = code + '\n'; // To make sure loops and functions fire
        attrs.height = 300;
      }

      if (parts[1] === 'python3' && parts[2] === 'console') {
        code = code + '\n'; // To make sure loops and functions fire
        url = url + '&runMode=console&outputOnly=true&runOption=console&leftMenu=true';
      }

      for(var key in attrs) {
        attrStr += ' ' + key + '="' + attrs[key] + '"';
      }

      url    = url + '#code=' + encodeURIComponent(code);

      url    = url.replace(/'/g, "%27");
      output = '<iframe class="embedded-trinket" src="' + url + '"' + attrStr + ' frameborder="0" marginwidth="0" marginheight="0" allowfullscreen></iframe>';
      return output;
    }
    else if (hljs && hljs.getLanguage(lang)) {
      // hljs.highlight signature in highlight.js@^11 is highlight(code, {language})
      // (the legacy two-arg form is deprecated). Use the modern form here;
      // wrap in try/catch to fall back to the default code renderer if the
      // requested language is not registered or highlight.js raises.
      var highlighted;
      try {
        highlighted = hljs.highlight(code, { language: lang }).value;
      } catch (e) {
        return false;
      }
      return '<pre><code class="hljs">' + highlighted + '</code></pre>';
    }
    else {
      // Fall back to the default marked renderer for plain code blocks
      return false;
    }
  }

  function checkForEmbedUrl(href, title, text) {
    var match;
    for (var i = 0; i < EMBED_URLS.length; i++) {
      if (match = href.match(EMBED_URLS[i].regex)) {
        return '<iframe title="' + (title || text) + '"'
               + ' src="'
               + (EMBED_URLS[i].url ? EMBED_URLS[i].url(match) : match.input)
               + '" ' + EMBED_URLS[i].attrs + '></iframe>';
      }
    }

    return false;
  }

  function processImage(href, title, text) {
    if (text === "plotly") {
      var plotly_parts  = href.split(':')
        , plotly_user   = plotly_parts[0]
        , plotly_id     = plotly_parts[1]
        , plotly_width  = 640
        , plotly_height = 480
        , plotly_attr, plotly_code;

      if (/\s+=\d+(x\d+)?/.test(plotly_id)) {
        plotly_attr = /\s+=(\d+)(x(\d+))?/.exec(plotly_id);
        if (plotly_attr[1]) {
          plotly_width = plotly_attr[1];
        }
        if (plotly_attr[3]) {
          plotly_height = plotly_attr[3];
        }

        plotly_id = plotly_id.replace(/\s+=.+/, '');
      }

      plotly_code = "<iframe "
        + "width='" + plotly_width + "' "
        + "height='" + plotly_height + "' "
        + "frameborder='0' seamless='seamless' scrolling='no' "
        + "src='https://plot.ly/~" + plotly_user + "/" + plotly_id + "/.embed"
        + "?width=" + plotly_width + "&height=" + plotly_height + "'></iframe>";

      return plotly_code;
    }
    else {
      var embedUrl = checkForEmbedUrl(href, title, text);

      if (embedUrl) {
        return embedUrl;
      }

      if (/^\//.test(href)) {
        href = trinketConfig.getUrl(href);
      }

      if (/\s+=\d+x\d*/.test(href)) {
        var attr   = href.match(/\s+=(\d+)x(\d*)/);
        var width  = attr[1] || ""; // ? "width=" + attr[1] : "";
        var height = attr[2] || ""; // ? "height=" + attr[2] : "";
        var style  = "";
        var img;

        href = href.replace(attr[0], "");

        img = '<img src="' + href + '" alt="' + text + '"';

        if (width) {
          img  += ' width="' + width + '"';
          style = 'style="width: ' + width + 'px;';

          if (height) {
            img   += ' height="' + height + '"';
            style += ' height: ' + height + 'px"';
          }
          else {
            style += 'height: auto"';
          }

          img += ' style="' + style + '"';
        }

        if (title) {
          img += ' title="' + title + '"';
        }

        img += '>';

        return img;
      }
      else {
        // Fall back to the default marked renderer for normal images
        return false;
      }
    }
  }

  function processLink(href, title, text) {
    var ipynb, arg, attrs, html;

    var embed = checkForEmbedUrl(href, title, text);
    if (embed) {
      return embed;
    }

    if (/^trinket-widget$/.test(text)) {
      attrs = {};
      // accept arguments of the style x=y,x="y,z",x='y,z'
      while (arg = /(\w+)=(?:("|'|&quot;|&#39;)((?:(?=(\\?))\4.)*?)\2|()([^,]+))/.exec(href)) {
        attrs[arg[1]] = arg[3] || arg[6];
        href          = href.substr(arg[0].length);
      }

    }

    if (ipynb = href.match(IPYNB_REGEXP) && href.charAt(0) == '/') {
      return '<a href="http://nbviewer.org/urls/' + trinketConfig.get('apphostname') + href + '" title="' + title + '">' + text + '</a>';
    }
    else {
      // Build the default-style link, then optionally rewrite to open in a
      // new window for non-anchor hrefs (matches fork behavior at lines
      // 436-441 pre-remediation: the fork called the default renderer and
      // then ran a regex replace to inject target="_blank"; here we build
      // the markup directly to avoid an extra string substitution).
      var safeText  = text != null ? String(text) : '';
      var safeTitle = (title != null && title !== '') ? ' title="' + title + '"' : '';
      var link;

      if (href && href.charAt(0) === '#') {
        link = '<a href="' + href + '"' + safeTitle + '>' + safeText + '</a>';
      } else {
        link = '<a target="_blank" href="' + href + '"' + safeTitle + '>' + safeText + '</a>';
      }
      return link;
    }
  }

  function processListitem(text, task, checked) {
    // SECURITY / parity: marked@4's GFM task list handling pre-injects
    // `<input disabled="" type="checkbox">` into the listitem text BEFORE
    // this renderer runs (the fork on marked@0.3.2 did not, so the text
    // contained the literal `[ ]` / `[x]` and the fork's listitem replaced
    // it inline). To preserve the fork's exact output (an enabled checkbox
    // with class="list-item-checkbox" and the parent <li class="list-item">)
    // we detect task list items via the `task` parameter, strip the
    // marked-injected `<input ...>` prefix, and emit our own markup.
    if (task) {
      // strip the auto-injected `<input ...>` (with optional preceding/
      // trailing whitespace) from the start of `text` so we can prepend our
      // own. The pattern matches both checked and unchecked variants.
      var stripped = text.replace(/^\s*<input[^>]*type="checkbox"[^>]*>\s*/i, '');
      var checkbox = checked
        ? '<input type="checkbox" class="list-item-checkbox" checked="checked" />'
        : '<input type="checkbox" class="list-item-checkbox" />';
      return '<li class="list-item">' + checkbox + ' ' + stripped + '</li>';
    }
    // Backward-compat / belt-and-suspenders: if some upstream tokenizer
    // path leaves the literal `[ ]` / `[x]` in `text`, handle it the way
    // the fork's listitem did (pre-remediation lib/shared/trinket-markdown.js:455-464).
    if (/^\s*\[[x ]\]\s*/.test(text)) {
      text = text
        .replace(/^\s*\[ \]\s*/, '<input type="checkbox" class="list-item-checkbox" />')
        .replace(/^\s*\[x\]\s*/, '<input type="checkbox" class="list-item-checkbox" checked="checked" />');
      return '<li class="list-item">' + text + '</li>';
    } else {
      return '<li>' + text + '</li>';
    }
  }

  // SECURITY: Register the custom renderers ONCE at module load (idempotent —
  // marked.use merges into the default renderer; subsequent module loads
  // return the same cached export). Replaces the fork's per-call
  // marked.Renderer.prototype.<method> mutation pattern at lines 446-464
  // pre-remediation, which leaked across calls and was a source of fragility.
  marked.use({
    renderer: {
      code: processCode,
      image: processImage,
      link: processLink,
      listitem: processListitem
    }
  });

  module.exports = function(options) {
    return function(src) {
      // src should be a string; replace null and undefined with empty string
      if (typeof src === 'undefined' || src == null) {
        src = "";
      }

      // check for and "protect" MathJax by adding backticks (preserved from fork)
      src = src.replace(/(\$\$|\$\(|\)\$)/g, '$1`');

      // SECURITY: marked@4 API change — `marked` is no longer directly
      // callable; use `marked.parse(src)` (was `marked(src)` in the fork).
      var markup = marked.parse(src);

      // remove any code tags or backticks that were added to protect MathJax
      markup = markup.replace(/(\$\$|\$\(|\)\$)(<(?:\/)?code>|\`)/g, '$1');

      // SECURITY: post-process via sanitize-html to enforce the HTML
      // allow-list and iframe-src allow-list (replaces the fork's
      // marked.setOptions({sanitize: ...}) callback at lines 211-256
      // pre-remediation). This eliminates GHSA-x5pg-88wf-qq4p,
      // GHSA-rrrm-qjm4-v8hf, GHSA-5v2h-r2cx-5xgj, GHSA-hjcp-j389-59ff
      // (the marked-fork ReDoS HIGH severity class) by removing the fork
      // itself; sanitize-html maintains a clean security track record.
      markup = sanitizeHtml(markup, SANITIZE_OPTIONS);

      return markup;
    };
  };
