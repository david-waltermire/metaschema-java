/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.datatype.adapter;

import com.fasterxml.jackson.databind.jsonFormatVisitors.JsonFormatTypes;

import gov.nist.secauto.metaschema.core.datatype.AbstractDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IQNameItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IUriReferenceItem;
import gov.nist.secauto.metaschema.core.qname.EQNameFactory;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.net.URI;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Support for the Metaschema <a href=
 * "https://pages.nist.gov/metaschema/specification/datatypes/#uri-reference">uri-reference</a>
 * data type.
 */
public class QNameAdapter
    extends AbstractDataTypeAdapter<IEnhancedQName, IQNameItem> {
  @NonNull
  private static final List<IEnhancedQName> NAMES = ObjectUtils.notNull(
      List.of(
          EQNameFactory.instance().newQName(MetapathConstants.NS_METAPATH, "qname")));

  QNameAdapter() {
    super(IEnhancedQName.class, IQNameItem.class, IQNameItem::cast);
  }

  @Override
  public List<IEnhancedQName> getNames() {
    return NAMES;
  }

  @Override
  public JsonFormatTypes getJsonRawType() {
    return JsonFormatTypes.STRING;
  }

  @SuppressWarnings("null")
  @Override
  public IEnhancedQName parse(String value) {
	throw new UnsupportedOperationException("QNameAdapter does not support parse qualified namespaces or prefixes."); 
  }

  @Override
  public IEnhancedQName copy(Object obj) {
    // a URI is immutable
    return (IEnhancedQName) obj;
  }

  @Override
  public IQNameItem newItem(Object value) {
    IEnhancedQName item = toValue(value);
    return IQNameItem.valueOf(item);
  }
}
