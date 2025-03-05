package com.example.midterm.Midterm.Practical.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.people.v1.model.*;
import org.springframework.stereotype.Service;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.client.auth.oauth2.Credential;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ContactService {
    final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

    public ContactService() throws GeneralSecurityException, IOException {
    }

    public PeopleService getPeopleService(Credential credential) throws GeneralSecurityException, IOException {
        return new PeopleService.Builder(HTTP_TRANSPORT, JSON_FACTORY, credential)
                .setApplicationName("midterms")
                .build();
    }


    // GET CONTACTS
    public String getAllContacts(Credential accessToken) throws GeneralSecurityException, IOException {
        PeopleService peopleService = getPeopleService(accessToken);

        try {
            ListConnectionsResponse response = peopleService.people().connections()
                    .list("people/me")
                    .setPersonFields("names,emailAddresses,phoneNumbers")
                    .setPageSize(10)
                    .execute();

            // Check if connections are null before streaming
            if (response == null || response.getConnections() == null) {
                return new ObjectMapper().writeValueAsString(Collections.emptyList());
            }

            List<Map<String, Object>> contacts = response.getConnections().stream()
                    .filter(person -> person != null)
                    .map(person -> {
                        return Map.of(
                                "name", Optional.ofNullable(person.getNames())
                                        .filter(names -> !names.isEmpty())
                                        .map(names -> names.get(0).getDisplayName())
                                        .orElse("No Name"),
                                "email", Optional.ofNullable(person.getEmailAddresses())
                                        .map(emails -> emails.stream()
                                                .map(EmailAddress::getValue)
                                                .collect(Collectors.toList()))
                                        .orElse(Collections.emptyList()),
                                "phone", Optional.ofNullable(person.getPhoneNumbers())
                                        .map(phones -> phones.stream()
                                                .map(PhoneNumber::getValue)
                                                .collect(Collectors.toList()))
                                        .orElse(Collections.emptyList()),
                                "resourceName", Optional.ofNullable(person.getResourceName())
                                        .orElse("No Resource Name")
                        );
                    })
                    .collect(Collectors.toList());

            return new ObjectMapper().writeValueAsString(contacts);

        } catch (GoogleJsonResponseException e) {
            // Log the specific error and handle different types of Google API errors
            System.err.println("Google API Error: " + e.getDetails());

            // Check for specific error conditions
            if (e.getStatusCode() == 403) {
                throw new IOException("Permission denied. Check OAuth2 scopes and user consent.");
            }

            throw e;
        }
    }

//    public String getAllContacts(Credential accessToken) throws GeneralSecurityException, IOException {
//        PeopleService peopleService = getPeopleService(accessToken);
//
//        ListConnectionsResponse response = peopleService.people().connections()
//                .list("people/me")
//                .setPersonFields("names,emailAddresses,phoneNumbers")
//                .setPageSize(10)
//                .execute();
//
//        List<Map<String, Object>> contacts = response.getConnections().stream()
//                .map(person -> Map.of(
//                        "name", person.getNames() != null && !person.getNames().isEmpty()
//                                ? person.getNames().get(0).getDisplayName()
//                                : "No Name",
//                        "email", person.getEmailAddresses() != null
//                                ? person.getEmailAddresses().stream()
//                                .map(EmailAddress::getValue)
//                                .collect(Collectors.toList())
//                                : List.of(),
//                        "phone", person.getPhoneNumbers() != null
//                                ? person.getPhoneNumbers().stream()
//                                .map(PhoneNumber::getValue)
//                                .collect(Collectors.toList())
//                                : List.of(),
//                        "resourceName", person.getResourceName() != null
//                                ? person.getResourceName()
//                                : "No Resource Name"
//                ))
//                .collect(Collectors.toList());
//
//        return new ObjectMapper().writeValueAsString(contacts);
//    }

    // CREATE CONTACTS
    public Person createContact(Credential accessToken, String name, String email, String phone) throws GeneralSecurityException, IOException {
        PeopleService peopleService = getPeopleService(accessToken);
        Person newContact = new Person();

        String[] names = name.split(" ", 2);
        Name contactName = new Name()
                .setGivenName(names[0])
                .setFamilyName(names.length > 1 ? names[1] : "");
        newContact.setNames(Collections.singletonList(contactName));

        if (!phone.isEmpty()) {
            newContact.setPhoneNumbers(Collections.singletonList(new PhoneNumber().setValue(phone)));
        }
        if (!email.isEmpty()) {
            newContact.setEmailAddresses(Collections.singletonList(new EmailAddress().setValue(email)));
        }

        return peopleService.people().createContact(newContact).execute();
    }

    // DELETE CONTACTS
    public void deleteContact(Credential accessToken, String resourceName) throws GeneralSecurityException, IOException {
        PeopleService peopleService = getPeopleService(accessToken);
        peopleService.people().deleteContact(resourceName).execute();
    }
    public Person updateContact(Credential accessToken, String resourceName, String name, String email, String phone)
            throws GeneralSecurityException, IOException {

        PeopleService peopleService = getPeopleService(accessToken);
        Person existingContact = peopleService.people()
                .get(resourceName)
                .setPersonFields("names,emailAddresses,phoneNumbers,metadata")
                .execute();

        Person updatedContact = new Person().setEtag(existingContact.getEtag());
        List<String> updateFields = new ArrayList<>();

        // Split name into first and last name
        String[] nameParts = name.split(" ", 2);
        String firstName = nameParts[0];
        String lastName = nameParts.length > 1 ? nameParts[1] : "";

        if (!firstName.isEmpty() || !lastName.isEmpty()) {
            updatedContact.setNames(Collections.singletonList(new Name()
                    .setGivenName(firstName)
                    .setFamilyName(lastName)));
            updateFields.add("names");
        }

        if (phone != null && !phone.isEmpty()) {
            updatedContact.setPhoneNumbers(Collections.singletonList(new PhoneNumber().setValue(phone)));
            updateFields.add("phoneNumbers");
        }

        if (email != null && !email.isEmpty()) {
            updatedContact.setEmailAddresses(Collections.singletonList(new EmailAddress().setValue(email)));
            updateFields.add("emailAddresses");
        }

        if (updateFields.isEmpty()) {
            throw new IllegalArgumentException("No valid fields to update.");
        }

        return peopleService.people()
                .updateContact(resourceName, updatedContact)
                .setUpdatePersonFields(String.join(",", updateFields))
                .execute();
    }



}
