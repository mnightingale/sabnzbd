import { convertHTMLtoText } from "./basic.js";

ko.bindingHandlers.truncatedTextCenter = {
    update: function(element, valueAccessor, allBindingsAccessor) {
        var value = ko.utils.unwrapObservable(valueAccessor())
        if (!value) return
        var maxLength = 60;
        if(value.length > maxLength) {
            var charsToShow = maxLength - 3,
                frontChars = Math.ceil(charsToShow/2),
                backChars = Math.floor(charsToShow/2);
            var truncatedValue = convertHTMLtoText(value.substr(0, frontChars)) + '&hellip;' +  convertHTMLtoText(value.substr(value.length - backChars));
        } else {
            var truncatedValue = convertHTMLtoText(value);
        }
        ko.bindingHandlers.html.update(element, function() {
            return truncatedValue;
        });
    }
};
ko.bindingHandlers.longText = {
    update: function(element, valueAccessor, allBindingsAccessor) {
        // Input is an array
        var value = ko.utils.unwrapObservable(valueAccessor())

        // Convert HTML entities for all but the Script (because of the (more)-link)
        if(allBindingsAccessor.get('longTextType') != "Script") {
            value = value.map(convertHTMLtoText)
        }

        // Any <br>'s?
        var outputText = '';
        if(value.length > 4) {
            // Inital 3, then the button, then the closing
            outputText += value.shift() + '<br />' + value.shift() + '<br />' + value.shift() + ' ';
            outputText += '<a href="#" class="history-status-more">(' + glitterTranslate.moreText + ')</a><br />';
            outputText += '<span class="history-status-hidden">';
            outputText += value.join('<br />');
            outputText += '</span>';
        } else {
            // Nothing special
            outputText += value.join('<br />');
        }

        // Replace link to our website
        outputText = outputText.replace('https://sabnzbd.org/not-complete', '<a href="https://sabnzbd.org/not-complete" class="history-status-dmca" target="_blank">https://sabnzbd.org/not-complete</a>')

        ko.bindingHandlers.html.update(element, function() {
            return outputText;
        });
    }
};
// Adapted for SABnzbd usage
ko.bindingHandlers.filedrop = {
    init: function(element, valueAccessor) {
        var options = $.extend({}, {
            overlaySelector: null
        }, valueAccessor());
        if(!options.onFileDrop)
            return;
        else if(!window.File || !window.FileReader || !window.FileList || !window.FormData) {
            console.log("File drop disabled because this browser is too old");
            return;
        }
        // EDITED to prevent drag-and-drop from inside own screen
        $(element).bind("dragstart", function(e) {
            $(element).data('internal-drag', true)
            // Remove after timeout
            setTimeout(function() {
                $(element).data('internal-drag', false)
            }, 2000)
        });
        $(element).bind("dragenter", function(e) {
            e.stopPropagation();
            e.preventDefault();
            // Was it external or internal?
            if($(element).data('internal-drag'))
                return;
            if(options.overlaySelector)
                $(options.overlaySelector).show();
        });
        $(element).bind("dragleave", function(e) {
            e.stopPropagation();
            e.preventDefault();
            // EDITED FOR FIREFOX!
            // Without the check for is(), the screen will blink in firefox!
            if(options.overlaySelector && $(e.target).is('.main-filedrop'))
                $(options.overlaySelector).hide();
        });
        $(element).bind("drop", function(e) {
            e.stopPropagation();
            e.preventDefault();
            if(options.overlaySelector)
                $(options.overlaySelector).hide();
            if(typeof options.onFileDrop === "function") {
                options.onFileDrop(e.originalEvent.dataTransfer.files)
            }
        });
    }
};
$(document).bind('dragover', function(e) {
    e.preventDefault();
});

/*! Knockout Persist - v0.1.0 - 2015-12-28
* https://github.com/spoike/knockout.persist
* Copyright (c) 2013 Mikael Brassman; Licensed MIT
* Safihre edited to better detect if localStorage is possible */
(function(ko) {
    // Don't crash on browsers that are missing localStorage
    try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
    } catch(e) {
        return false;
    }

    ko.extenders.persist = function(target, key) {
        var initialValue = target();
        // Load existing value from localStorage if set
        if (key && localStorage.getItem(key) !== null) {
            try {
                initialValue = JSON.parse(localStorage.getItem(key));
            } catch (e) {
            }
        }
        target(initialValue);
        // Subscribe to new values and add them to localStorage
        target.subscribe(function (newValue) {
            localStorage.setItem(key, ko.toJSON(newValue));
        });
        return target;
    };
})(ko);

ko.bindingHandlers.slider = {
    init: function(element, valueAccessor, allBindingsAccessor) {
        var options = allBindingsAccessor().sliderOptions || {};
        $(element).slider(options);
        /* This created many update signallings when nothing changed
        ko.utils.registerEventHandler(element, "slidechange", function(event, ui) {
            var observable = valueAccessor();
            observable(ui.value);
        });*/
        ko.utils.domNodeDisposal.addDisposeCallback(element, function() {
            $(element).slider("destroy");
        });
        ko.utils.registerEventHandler(element, "slide", function(event, ui) {
            var observable = valueAccessor();
            observable(ui.value);
        });
    },
    update: function(element, valueAccessor) {
        var value = ko.utils.unwrapObservable(valueAccessor());
        if(isNaN(value)) value = 0;
        $(element).slider("value", value);
    }
};
