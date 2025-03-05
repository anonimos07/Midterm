package com.example.midterm.Midterm.Practical.Controller;


import org.springframework.ui.Model;
import com.example.midterm.Midterm.Practical.Service.ContactService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Controller
public class ContactController {

    @Autowired
    private ContactService googleContactsService;
    @Autowired
    private OAuth2AuthorizedClientService authorizeClientService;
    @Autowired
    private OAuth2AuthorizedClientManager authorizedClientManager;

    public String getToken() {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizedClient client = authorizeClientService.loadAuthorizedClient(token.getAuthorizedClientRegistrationId(), token.getName());

        if (client == null || client.getAccessToken() == null) {
            throw new RuntimeException("OAuth2 client or access token not found.");
        }

        OAuth2AccessToken accessToken = client.getAccessToken();
        if (accessToken.getExpiresAt().isBefore(Instant.now())) {
            client = authorizedClientManager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId(token.getAuthorizedClientRegistrationId())
                    .principal(token)
                    .build());
            if (client == null) {
                throw new RuntimeException("Failed to refresh the access token.");
            }
            accessToken = client.getAccessToken();
        }

        return accessToken.getTokenValue();
    }

    private Credential getCredential(String token){
        return new Credential(BearerToken.authorizationHeaderAccessMethod()).setAccessToken(token);
    }

    @RequestMapping("/")
    public String index(){
        return "index";
    }

    @RequestMapping("/login.html")
    public String login(){
        return "login";
    }

    @GetMapping("/display.html")
    public String display(Model model) throws GeneralSecurityException, IOException {
        System.out.println("Fetching credentials...");
        Credential credential = getCredential(getToken());
        System.out.println("Credentials obtained: " + credential);

        System.out.println("Fetching contacts...");
        String jsonResponse = googleContactsService.getAllContacts(credential);
        System.out.println("JSON Response: " + jsonResponse);

        if (jsonResponse == null || jsonResponse.isEmpty()) {
            System.out.println("Error: JSON response is empty.");
            throw new IOException("No contacts data received.");
        }

        List<Map<String, Object>> contacts = new ObjectMapper().readValue(
                jsonResponse, new TypeReference<List<Map<String, Object>>>() {}
        );


        model.addAttribute("contacts", contacts);
        System.out.println("Contacts successfully added to model.");

        return "display";
    }


    @PostMapping("/create-contact")
    public String createContact(String name, String email, String phone) throws GeneralSecurityException, IOException {
        Credential credential = getCredential(getToken());
        googleContactsService.createContact(credential, name, email, phone);
        return "redirect:/display.html";
    }

    @PostMapping("/update-contact")
    public String updateContact(String resourceName, String name, String email, String phone) throws GeneralSecurityException, IOException {
        Credential credential = getCredential(getToken());
        googleContactsService.updateContact(credential, resourceName, name, email, phone);
        return "redirect:/display.html";
    }

    @PostMapping("/delete-contact")
    public String deleteContact(String resourceName) throws GeneralSecurityException, IOException {
        Credential credential = getCredential(getToken());
        googleContactsService.deleteContact(credential, resourceName);
        return "redirect:/display.html";
    }

}
