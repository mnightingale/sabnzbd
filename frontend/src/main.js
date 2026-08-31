import { checkAllFiles, displayDateTime, hideCompletedFiles, keepOpen, localStorageGetItem, localStorageSetItem, showDetails } from "./basic.js";
import { ViewModel } from "./viewmodel.js";
import "./knockout-extensions.js";

const translations = document.getElementById("sab-translations");

// Knockout binding expressions and inline handlers in the templates resolve against the window
Object.assign(window, {
    glitterTranslate: translations ? JSON.parse(translations.textContent) : {},
    checkAllFiles,
    displayDateTime,
    hideCompletedFiles,
    keepOpen,
    localStorageGetItem,
    localStorageSetItem,
    showDetails,
});

jQuery(function () {
    ko.applyBindings(new ViewModel(), document.getElementById("sabnzbd"));
});
