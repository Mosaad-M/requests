# ============================================================================
# psl.mojo — Curated Public Suffix List (PSL) for cookie domain validation
# ============================================================================
#
# Purpose: prevent "supercookies" where Domain=.co.uk or Domain=.github.io
# would match any subdomain under a public suffix.
#
# This is a curated subset of publicsuffix.org covering the most-used
# country-code second-level registries and popular hosting platforms.
# For the full PSL, see https://publicsuffix.org/list/public_suffix_list.dat
#
# Usage:
#   from psl import is_public_suffix
#   if is_public_suffix("co.uk"):         → True  (reject Domain=.co.uk)
#   if is_public_suffix("example.co.uk"): → False (valid registrable domain)
# ============================================================================

# All known public suffixes packed into a pipe-delimited string.
# Search: "|" + domain + "|" to avoid prefix/suffix false matches.
alias _PSL = (
    # Country-code TLDs with second-level registries
    # United Kingdom
    "|co.uk|org.uk|me.uk|net.uk|ltd.uk|plc.uk|sch.uk"
    "|gov.uk|mod.uk|mil.uk|nhs.uk|police.uk"
    # Australia
    "|com.au|net.au|org.au|edu.au|gov.au|asn.au|id.au"
    # New Zealand
    "|co.nz|net.nz|org.nz|edu.nz|gov.nz|geek.nz"
    # Japan
    "|co.jp|ne.jp|or.jp|go.jp|ed.jp|ac.jp|lg.jp"
    # South Africa
    "|co.za|org.za|gov.za|edu.za|net.za|web.za"
    # Brazil
    "|com.br|net.br|org.br|gov.br|edu.br|mil.br"
    # India
    "|co.in|net.in|org.in|edu.in|gov.in|mil.in|res.in"
    # China
    "|com.cn|net.cn|org.cn|gov.cn|edu.cn|mil.cn"
    # Hong Kong
    "|com.hk|net.hk|org.hk|gov.hk|edu.hk|idv.hk"
    # Taiwan
    "|com.tw|net.tw|org.tw|gov.tw|edu.tw|idv.tw"
    # Singapore
    "|com.sg|net.sg|org.sg|gov.sg|edu.sg|per.sg"
    # Malaysia
    "|com.my|net.my|org.my|gov.my|edu.my|mil.my"
    # South Korea
    "|co.kr|or.kr|go.kr|re.kr|pe.kr|mil.kr|ac.kr"
    # Argentina
    "|com.ar|net.ar|org.ar|gov.ar|edu.ar|mil.ar"
    # Mexico
    "|com.mx|net.mx|org.mx|gob.mx|edu.mx"
    # Spain
    "|com.es|org.es|gob.es|edu.es|nom.es"
    # Italy
    "|co.it"
    # Russia
    "|com.ru|net.ru|org.ru|pp.ru"
    # Ukraine
    "|com.ua|net.ua|org.ua|gov.ua|edu.ua"
    # Pakistan
    "|com.pk|net.pk|org.pk|gov.pk|edu.pk"
    # Bangladesh
    "|com.bd|net.bd|org.bd|gov.bd|edu.bd"
    # Sri Lanka
    "|com.lk|net.lk|org.lk|gov.lk|edu.lk"
    # Nigeria
    "|com.ng|net.ng|org.ng|gov.ng|edu.ng"
    # Kenya
    "|co.ke|or.ke|go.ke|ne.ke"
    # Egypt
    "|com.eg|net.eg|org.eg|gov.eg|edu.eg"
    # UAE
    "|co.ae|net.ae|org.ae|gov.ae|edu.ae"
    # Saudi Arabia
    "|com.sa|net.sa|org.sa|gov.sa|edu.sa"
    # Turkey
    "|com.tr|net.tr|org.tr|gov.tr|edu.tr|k12.tr"
    # Poland
    "|com.pl|net.pl|org.pl|gov.pl|edu.pl"
    # Czech Republic
    "|co.cz"
    # Philippines
    "|com.ph|net.ph|org.ph|gov.ph|edu.ph"
    # Indonesia
    "|co.id|net.id|or.id|go.id|web.id|ac.id"
    # Thailand
    "|co.th|net.th|org.th|go.th|ac.th"
    # Vietnam
    "|com.vn|net.vn|org.vn|gov.vn|edu.vn"
    # Popular hosting / platform suffixes
    "|github.io|gitlab.io|gitbook.io"
    "|netlify.app|vercel.app"
    "|pages.dev|workers.dev"
    "|herokuapp.com"
    "|firebaseapp.com|web.app|appspot.com"
    "|s3.amazonaws.com|cloudfront.net|elb.amazonaws.com"
    "|azurewebsites.net|azurestaticapps.net|blob.core.windows.net|trafficmanager.net"
    "|ondigitalocean.app|fly.dev|render.com|surge.sh"
    "|bitbucket.io|codepen.io|codesandbox.io|glitch.me"
    "|repl.co|replit.dev|pythonanywhere.com|000webhostapp.com"
    "|stackblitz.io|web.fc2.com"
    "|"  # trailing pipe — every entry is bounded by |...|
)


fn is_public_suffix(domain: String) -> Bool:
    """Return True if `domain` is a well-known public suffix.

    Searches a pipe-delimited table for "|domain|" to avoid prefix/suffix
    false matches. Case-sensitive (cookie domains are already lowercased by
    the time this is called from _jar_store).

    Examples:
      is_public_suffix("co.uk")         → True
      is_public_suffix("github.io")     → True
      is_public_suffix("example.co.uk") → False
      is_public_suffix("example.com")   → False
    """
    var needle = "|" + domain + "|"
    var needle_bytes = needle.as_bytes()
    var haystack_bytes = _PSL.as_bytes()
    var n = len(needle_bytes)
    var h = len(haystack_bytes)
    if n > h:
        return False
    for i in range(h - n + 1):
        var found = True
        for j in range(n):
            if haystack_bytes[i + j] != needle_bytes[j]:
                found = False
                break
        if found:
            return True
    return False
