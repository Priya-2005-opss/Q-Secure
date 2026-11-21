
package com.qsecure.qsecure;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DevToolsTestController {

    @GetMapping("/api/devtools-test")
    public String testDevTools() {
        return "Q-Secure DevTools is working! Version 3";
    }
}
