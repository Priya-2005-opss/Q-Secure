
package com.qsecure.qsecure;

import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.*;

@Service
public class DnsAuthenticationService {

    public Map<String, String> checkDomain(
            String domain, String selector) {

        Map<String, String> results = new LinkedHashMap<>();

        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException(
                "A valid sender domain is required."
            );
        }

        domain = domain.trim().toLowerCase(Locale.ROOT);

        if (!domain.matches(
                "(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
            throw new IllegalArgumentException(
                "Invalid domain format."
            );
        }

        results.put(
            "SPF",
            checkTxtRecord(domain, "v=spf1")
        );

        results.put(
            "DMARC",
            checkTxtRecord("_dmarc." + domain, "v=dmarc1")
        );

        if (selector != null &&
            !selector.isBlank() &&
            selector.matches("[a-zA-Z0-9._-]{1,100}")) {

            results.put(
                "DKIM",
                checkTxtRecord(
                    selector + "._domainkey." + domain,
                    "v=dkim1"
                )
            );

        } else {
            results.put(
                "DKIM",
                "SELECTOR REQUIRED"
            );
        }

        return results;
    }

    private String checkTxtRecord(
            String domain, String expectedPrefix) {

        Hashtable<String, String> environment =
            new Hashtable<>();

        environment.put(
            Context.INITIAL_CONTEXT_FACTORY,
            "com.sun.jndi.dns.DnsContextFactory"
        );

        environment.put("com.sun.jndi.dns.timeout.initial", "3000");
        environment.put("com.sun.jndi.dns.timeout.retries", "1");

        DirContext context = null;

        try {
            context = new InitialDirContext(environment);

            Attributes attributes = context.getAttributes(
                "dns:/" + domain,
                new String[]{"TXT"}
            );

            Attribute txtRecords = attributes.get("TXT");

            if (txtRecords == null || txtRecords.size() == 0) {
                return "NOT FOUND";
            }

            NamingEnumeration<?> records = txtRecords.getAll();

            while (records.hasMore()) {

                String record = records.next().toString();

                if (record.toLowerCase(Locale.ROOT)
                        .contains(expectedPrefix.toLowerCase(Locale.ROOT))) {

                    return "FOUND";
                }
            }

            return "NOT FOUND";

        } catch (Exception e) {

            return "DNS LOOKUP ERROR";

        } finally {

            if (context != null) {
                try {
                    context.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
