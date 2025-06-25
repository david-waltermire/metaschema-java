/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.databind.model.metaschema.impl;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.datatype.adapter.MetaschemaDataTypeProvider;
import gov.nist.secauto.metaschema.core.datatype.markup.MarkupMultiline;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.metapath.item.node.IAssemblyNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IDocumentNodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.IAtomicOrUnionType;
import gov.nist.secauto.metaschema.core.model.IAttributable;
import gov.nist.secauto.metaschema.core.model.IDefinition;
import gov.nist.secauto.metaschema.core.model.IFieldInstance;
import gov.nist.secauto.metaschema.core.model.IGroupable;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.model.JsonGroupAsBehavior;
import gov.nist.secauto.metaschema.core.model.XmlGroupAsBehavior;
import gov.nist.secauto.metaschema.core.qname.IEnhancedQName;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.model.IGroupAs;
import gov.nist.secauto.metaschema.databind.model.annotations.ModelUtil;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingMetaschemaModule;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.GroupingAs;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.METASCHEMA.DefineAssembly.RootName;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.Property;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.Remarks;
import gov.nist.secauto.metaschema.databind.model.metaschema.binding.UseName;

import java.math.BigInteger;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public final class ModelSupport {
  private ModelSupport() {
    // disable construction
  }

  @NonNull
  public static Map<IAttributable.Key, Set<String>> parseProperties(@NonNull List<Property> props) {
    return CollectionUtil.unmodifiableMap(ObjectUtils.notNull(props.stream()
        .collect(
            Collectors.groupingBy(
                prop -> {
                  String name = ObjectUtils.requireNonNull(prop.getName());
                  URI namespace = prop.getNamespace();
                  return namespace == null ? IAttributable.key(name)
                      : IAttributable.key(name, ObjectUtils.notNull(namespace.toASCIIString()));
                },
                Collectors.mapping(
                    prop -> ObjectUtils.requireNonNull(prop.getValue()),
                    Collectors.toCollection(LinkedHashSet::new))))));
  }

  public static boolean yesOrNo(String allowOther) {
    return "yes".equals(allowOther);
  }

  /**
   * Translate a text scope value to the equivalent enumerated value.
   *
   * @param value
   *          the text scope value
   * @return the enumerated value
   */
  @NonNull
  public static IDefinition.ModuleScope moduleScope(@NonNull String value) {
    IDefinition.ModuleScope retval;
    switch (value) {
    case "local":
      retval = IDefinition.ModuleScope.PRIVATE;
      break;
    case "global":
    default:
      retval = IDefinition.ModuleScope.PUBLIC;
    }
    return retval;
  }

  @Nullable
  public static Integer index(@Nullable BigInteger index) {
    return index == null ? null : index.intValueExact();
  }

  @Nullable
  public static String useName(@Nullable UseName useName) {
    return useName == null ? null : useName.getName();
  }

  @Nullable
  public static Integer useIndex(@Nullable UseName useName) {
    Integer retval = null;
    if (useName != null) {
      BigInteger index = useName.getIndex();
      if (index != null) {
        retval = index.intValueExact();
      }
    }
    return retval;
  }

  @Nullable
  public static MarkupMultiline remarks(@Nullable Remarks remarks) {
    return remarks == null ? null : remarks.getRemark();
  }

  @NonNull
  public static IDataTypeAdapter<?> dataType(
      @Nullable String dataType,
      @NonNull ISource source) {
    IDataTypeAdapter<?> retval;
    if (dataType == null) {
      retval = MetaschemaDataTypeProvider.DEFAULT_DATA_TYPE;
    } else {
      IEnhancedQName qname = IEnhancedQName.of(MetapathConstants.NS_METAPATH, dataType);
      IAtomicOrUnionType<?> type;
      try {
        source.getStaticContext();
        type = StaticContext.lookupAtomicType(qname);
      } catch (StaticMetapathException ex) {
        throw new IllegalStateException("Unrecognized data type: " + qname, ex);

      }
      retval = type.getAdapter();
      if (retval == null) {
        throw new IllegalStateException("No type adapter registered for data type: " + qname);
      }
    }
    return retval;
  }

  @Nullable
  public static Object defaultValue(
      @Nullable String defaultValue,
      @NonNull IDataTypeAdapter<?> javaTypeAdapter) {
    return defaultValue == null ? null : ModelUtil.resolveDefaultValue(defaultValue, javaTypeAdapter);
  }

  public static int maxOccurs(@NonNull String maxOccurs) {
    return "unbounded".equals(maxOccurs) ? -1 : Integer.parseInt(maxOccurs);
  }

  public static String rootName(@Nullable RootName rootName) {
    return rootName == null ? null : rootName.getName();
  }

  public static Integer rootIndex(@Nullable RootName rootName) {
    Integer retval = null;
    if (rootName != null) {
      BigInteger index = rootName.getIndex();
      if (index != null) {
        retval = index.intValueExact();
      }
    }
    return retval;
  }

  public static boolean fieldInXml(@Nullable String inXml) {
    boolean retval = IFieldInstance.DEFAULT_FIELD_IN_XML_WRAPPED;
    if (inXml != null) {
      switch (inXml) {
      case "WRAPPED":
      case "WITH_WRAPPER":
        retval = true;
        break;
      default:
        retval = false;
        break;
      }
    }
    return retval;
  }

  @NonNull
  public static IGroupAs groupAs(
      @Nullable GroupingAs groupAs,
      @NonNull IModule module) {
    return groupAs == null
        ? IGroupAs.SINGLETON_GROUP_AS
        : new GroupAsImpl(groupAs, module);
  }

  @NonNull
  public static JsonGroupAsBehavior groupAsJsonBehavior(@Nullable String inJson) {
    JsonGroupAsBehavior retval = IGroupable.DEFAULT_JSON_GROUP_AS_BEHAVIOR;
    if (inJson != null) {
      switch (inJson) {
      case "ARRAY":
        retval = JsonGroupAsBehavior.LIST;
        break;
      case "SINGLETON_OR_ARRAY":
        retval = JsonGroupAsBehavior.SINGLETON_OR_LIST;
        break;
      case "BY_KEY":
        retval = JsonGroupAsBehavior.KEYED;
        break;
      default:
        retval = IGroupable.DEFAULT_JSON_GROUP_AS_BEHAVIOR;
        break;
      }
    }
    return retval;
  }

  @NonNull
  public static XmlGroupAsBehavior groupAsXmlBehavior(@Nullable String inXml) {
    XmlGroupAsBehavior retval = IGroupable.DEFAULT_XML_GROUP_AS_BEHAVIOR;
    if (inXml != null) {
      switch (inXml) {
      case "GROUPED":
        retval = XmlGroupAsBehavior.GROUPED;
        break;
      case "UNGROUPED":
        retval = XmlGroupAsBehavior.UNGROUPED;
        break;
      default:
        retval = IGroupable.DEFAULT_XML_GROUP_AS_BEHAVIOR;
        break;
      }
    }
    return retval;
  }

  @SuppressWarnings("unchecked")
  @Nullable
  public static <NODE extends IAssemblyNodeItem> NODE toNodeItem(
      @NonNull IBindingMetaschemaModule module,
      @NonNull IEnhancedQName definitionQName,
      int position) {
    IDocumentNodeItem moduleNodeItem = module.getSourceNodeItem();
    return (NODE) moduleNodeItem.getModelItemsByName(definitionQName).get(position);
  }
}
