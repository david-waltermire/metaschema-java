
package gov.nist.secauto.metaschema.core.metapath.type;

import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AnyItemType;
import gov.nist.secauto.metaschema.core.metapath.type.impl.AnyRawItemType;
import gov.nist.secauto.metaschema.core.metapath.type.impl.ArrayTest;
import gov.nist.secauto.metaschema.core.metapath.type.impl.DataTypeItemType;

import edu.umd.cs.findbugs.annotations.NonNull;

public interface IItemType {
  @NonNull
  static IItemType item() {
    return AnyItemType.instance();
  }

  static IItemType function() {
    return AnyRawItemType.ANY_FUNCTION;
  }

  // static IFunctionTest function(@NonNull ISequenceType result, @NonNull
  // ISequenceType... args) {
  //
  // }

  static IItemType map() {
    return AnyRawItemType.ANY_MAP;
  }

  // static IMapTest map(@NonNull IAtomicOrUnionType key, @NonNull ISequenceType
  // value) {
  //
  // }

  static IItemType array() {
    return AnyRawItemType.ANY_ARRAY;
  }

  static IArrayTest array(@NonNull ISequenceType value) {
    return new ArrayTest(value);
  }

  static IItemType type(@NonNull IDataTypeAdapter<?> adapter) {
    return new DataTypeItemType(adapter);
  }

  boolean matches(@NonNull IItem item);

  @NonNull
  Class<? extends IItem> getItemClass();

  @NonNull
  String toSignature();

  static IItemType node(Class<? extends INodeItem> itemClass, String nodeName) {
  }
}
