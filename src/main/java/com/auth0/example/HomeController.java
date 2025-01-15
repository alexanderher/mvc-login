package com.auth0.example;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller for the home page.
 */
@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            model.addAttribute("profile", principal.getClaims());
            model.addAttribute("token", principal.getIdToken().getTokenValue());
        }
        return "index";
    }

    @GetMapping("/login-auth")
    public String loginAuth(Model model, @AuthenticationPrincipal OidcUser principal) {
        System.out.println("entrooo 3000");
        if (principal != null) {
            model.addAttribute("profile", principal.getClaims());
            model.addAttribute("token", principal.getIdToken().getTokenValue());
        }
        return "index";
    }

    @GetMapping("/backchannel-logout")
    public String logout(Model model, @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            model.addAttribute("profile", principal.getClaims());
            model.addAttribute("token", principal.getIdToken().getTokenValue());
        }
        return "index";
    }
}