/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

import gov.nist.secauto.metaschema.core.datatype.IDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.function.IFunctionLibrary;
import gov.nist.secauto.metaschema.core.metapath.function.library.DefaultFunctionLibrary;

module gov.nist.secauto.metaschema.core {
  // requirements
  requires java.base;
  requires java.xml;

  requires static org.eclipse.jdt.annotation;
  requires static biz.aQute.bnd.util;
  requires static com.google.auto.service;
  requires com.github.spotbugs.annotations;
  // requires static org.jetbrains.annotations;

  requires com.ctc.wstx;
  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.core;
  requires transitive com.fasterxml.jackson.databind;
  requires transitive inet.ipaddr;
  requires nl.talsmasoftware.lazy4j;
  requires org.antlr.antlr4.runtime;
  requires org.apache.commons.lang3;
  requires org.apache.commons.text;
  requires org.apache.logging.log4j;
  requires transitive org.apache.xmlbeans;
  requires transitive org.codehaus.stax2;
  requires transitive org.json;
  requires org.jsoup;

  // dependencies without a module descriptor
  requires transitive everit.json.schema; // needed for validation details
  requires transitive flexmark;
  requires flexmark.ext.escaped.character;
  requires flexmark.ext.gfm.strikethrough;
  requires flexmark.ext.superscript;
  requires transitive flexmark.ext.tables;
  requires transitive flexmark.ext.typographic;
  requires transitive flexmark.html2md.converter;
  requires transitive flexmark.util.ast;
  requires flexmark.util.builder;
  requires flexmark.util.collection;
  requires transitive flexmark.util.data;
  requires flexmark.util.dependency;
  requires flexmark.util.format;
  requires flexmark.util.html;
  requires flexmark.util.misc;
  requires transitive flexmark.util.sequence;
  requires flexmark.util.visitor;

  exports gov.nist.secauto.metaschema.core.configuration;
  exports gov.nist.secauto.metaschema.core.datatype;
  exports gov.nist.secauto.metaschema.core.datatype.adapter;
  exports gov.nist.secauto.metaschema.core.datatype.markup;
  exports gov.nist.secauto.metaschema.core.datatype.object;
  exports gov.nist.secauto.metaschema.core.metapath;
  exports gov.nist.secauto.metaschema.core.metapath.format;
  exports gov.nist.secauto.metaschema.core.metapath.function;
  exports gov.nist.secauto.metaschema.core.metapath.function.library;
  exports gov.nist.secauto.metaschema.core.metapath.item;
  exports gov.nist.secauto.metaschema.core.metapath.item.atomic;
  exports gov.nist.secauto.metaschema.core.metapath.item.function;
  exports gov.nist.secauto.metaschema.core.metapath.item.node;
  exports gov.nist.secauto.metaschema.core.metapath.type;
  exports gov.nist.secauto.metaschema.core.model;
  exports gov.nist.secauto.metaschema.core.model.constraint;
  exports gov.nist.secauto.metaschema.core.model.util;
  exports gov.nist.secauto.metaschema.core.model.validation;
  exports gov.nist.secauto.metaschema.core.model.xml;
  exports gov.nist.secauto.metaschema.core.resource;
  exports gov.nist.secauto.metaschema.core.util;

  exports gov.nist.secauto.metaschema.core.datatype.markup.flexmark
      to gov.nist.secauto.metaschema.databind;

  // make bundled schemas and related resources available for use
  opens schema.json;
  opens schema.xml;
  opens schema.metaschema;

  // allow reflection on data types
  opens gov.nist.secauto.metaschema.core.datatype.markup;

  // need to allow access to the generated XMLBeans files
  opens org.apache.xmlbeans.metadata.system.metaschema;
  opens gov.nist.secauto.metaschema.core.model.xml.xmlbeans;
  opens gov.nist.secauto.metaschema.core.model.xml.xmlbeans.impl;

  // services
  uses IDataTypeProvider;
  uses IFunctionLibrary;

  provides IFunctionLibrary with DefaultFunctionLibrary;
  provides IDataTypeProvider with MetaschemaDataTypeProvider, MarkupDataTypeProvider;
}
