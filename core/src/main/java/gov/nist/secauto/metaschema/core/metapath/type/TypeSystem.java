/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFieldNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFlagNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("removal")
public final class TypeSystem {
  private static final Map<Class<? extends IItem>, IItemType> ITEM_CLASS_TO_TYPE_MAP;

  static {
    ITEM_CLASS_TO_TYPE_MAP = Collections.unmodifiableMap(Map.ofEntries(
        register(IItemType.item()),
        register(IItemType.node(INodeItem.class, "node")),
        register(IItemType.node(IDocumentNodeItem.class, "document-node")),
        register(IItemType.node(IAssemblyNodeItem.class, "assembly-node")),
        register(IItemType.node(IFieldNodeItem.class, "field-node")),
        register(IItemType.node(IFlagNodeItem.class, "flag-node")),
        register(IArrayItem.class, "array"),
        register(IMapItem.class, "map"),
        register(IAnyAtomicItem.class, "any-atomic-type"),
        register(INumericItem.class, "numeric"),
        register(IDurationItem.class, "duration"),
        register(MetaschemaDataTypeProvider.BASE64),
        register(MetaschemaDataTypeProvider.BOOLEAN),
        register(MetaschemaDataTypeProvider.DATE),
        register(MetaschemaDataTypeProvider.DATE_TIME),
        register(MetaschemaDataTypeProvider.IP_V4_ADDRESS),
        register(MetaschemaDataTypeProvider.IP_V6_ADDRESS),
        register(MetaschemaDataTypeProvider.URI),
        register(MetaschemaDataTypeProvider.URI_REFERENCE),
        register(MetaschemaDataTypeProvider.UUID),
        register(MetaschemaDataTypeProvider.DAY_TIME_DURATION),
        register(MetaschemaDataTypeProvider.YEAR_MONTH_DURATION),
        register(MetaschemaDataTypeProvider.DECIMAL),
        register(MetaschemaDataTypeProvider.INTEGER),
        register(MetaschemaDataTypeProvider.NON_NEGATIVE_INTEGER),
        register(MetaschemaDataTypeProvider.POSITIVE_INTEGER),
        register(MetaschemaDataTypeProvider.EMAIL_ADDRESS),
        register(MetaschemaDataTypeProvider.HOSTNAME),
        register(MetaschemaDataTypeProvider.NCNAME),
        register(MetaschemaDataTypeProvider.STRING),
        register(MetaschemaDataTypeProvider.TOKEN)));

  }

  private static Map.Entry<Class<? extends IItem>, IItemType> register(
      @NonNull IItemType type) {
    return Map.entry(type.getItemClass(), type);
  }

  private static Map.Entry<Class<? extends IItem>, IItemType> register(
      @NonNull IDataTypeAdapter<?> adapter) {
    register(IItemType.type(adapter));
  }

  private static Map.Entry<Class<? extends IItem>, QName> register(
      @NonNull Class<? extends INodeItem> clazz,
      @NonNull String typeName) {
    return Map.entry(clazz, new QName(MetapathConstants.NS_METAPATH.toASCIIString(), typeName));
  }

  @NonNull
  private static Stream<Class<? extends IItem>> getItemInterfaces(@NonNull Class<?> clazz) {
    @SuppressWarnings("unchecked") Stream<Class<? extends IItem>> retval = IItem.class.isAssignableFrom(clazz)
        ? Stream.of((Class<? extends IItem>) clazz)
        : Stream.empty();

    Class<?>[] interfaces = clazz.getInterfaces();
    if (interfaces.length > 0) {
      retval = Stream.concat(retval, Arrays.stream(interfaces).flatMap(TypeSystem::getItemInterfaces));
    }

    return ObjectUtils.notNull(retval);
  }

  /**
   * Get the human-friendly data type name for the provided Metapath item class.
   *
   * @param clazz
   *          the Metapath item class to get the name for
   * @return the name or {@code null} if no name is registered for the item class
   */
  public static String getName(@NonNull Class<? extends IItem> clazz) {
    Class<? extends IItem> itemClass = getItemInterfaces(clazz).findFirst().orElse(null);

    QName qname = ITEM_CLASS_TO_QNAME_MAP.get(itemClass);
    return qname == null ? clazz.getName() : asPrefixedName(qname);
  }

  private static String asPrefixedName(@NonNull QName qname) {
    String namespace = qname.getNamespaceURI();
    String prefix = namespace.isEmpty() ? null : StaticContext.getWellKnownPrefixForUri(namespace);
    return prefix == null ? qname.toString() : prefix + ":" + qname.getLocalPart();
  }

  private TypeSystem() {
    // disable construction
  }
}
