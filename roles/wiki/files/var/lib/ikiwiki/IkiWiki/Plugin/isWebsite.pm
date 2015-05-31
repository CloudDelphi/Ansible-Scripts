#!/usr/bin/perl

package IkiWiki::Plugin::isWebsite;

use warnings;
use strict;
use IkiWiki 3.00;

sub import {
    hook(type => "pagetemplate", id => "isWebsite", call => \&pagetemplate);
}

sub pagetemplate (@) {
    my %params = @_;
    $params{template}->param(ISWEBSITE => 1) if $params{page} =~ /^website(?:\/.*)?$/;
}

1
