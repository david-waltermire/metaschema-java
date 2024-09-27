/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.item;

import gov.nist.secauto.metaschema.core.metapath.ICollectionValue;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IAnyAtomicItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IMapItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;

import java.io.PrintWriter;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Produces a textual representation of a Metapath sequence.
 */
public class DefaultItemWriter implements IItemWriter {

  @NonNull
  private final PrintWriter writer;
  @NonNull
  private final Visitor visitor = new Visitor();

  /**
   * Construct a new item writer.
   *
   * @param writer
   *          the writer to append text to
   */
  public DefaultItemWriter(@NonNull PrintWriter writer) {
    this.writer = writer;
  }

  @Override
  public void writeSequence(ISequence<?> sequence) {
    boolean wrap = sequence.size() != 1;
    if (wrap) {
      writer.append('(');
    }
    boolean first = true;
    for (IItem item : sequence) {

      if (first) {
        first = false;
      } else {
        writer.append(',');
      }

      item.accept(visitor);
    }

    if (wrap) {
      writer.append(')');
    }
  }

  @Override
  public void writeArray(IArrayItem<?> array) {
    writer.append('[');
    boolean first = true;
    for (ICollectionValue value : array) {
      assert value != null;

      if (first) {
        first = false;
      } else {
        writer.append(',');
      }

      writeCollectionValue(value);
    }
    writer.append(']');
  }

  @Override
  public void writeMap(IMapItem<?> map) {
    writer.append("map {");
    boolean first = true;
    for (ICollectionValue value : map.values()) {
      assert value != null;

      if (first) {
        first = false;
      } else {
        writer.append(',');
      }

      writeCollectionValue(value);
    }
    writer.append('}');
  }

  @Override
  public void writeNode(INodeItem node) {
    writer.append(node.getBaseUri().toString());
    writer.append('#');
    writer.append(node.getMetapath());
  }

  @Override
  public void writeAtomicValue(IAnyAtomicItem node) {
    writer.append(node.asString());
  }

  @Override
  public void writeFunction(IFunction function) {
    writer.append(function.toSignature());
  }

  /**
   * Write the provided collection value.
   *
   * @param value
   *          the value to write
   */
  protected void writeCollectionValue(@NonNull ICollectionValue value) {
    if (value instanceof IItem) {
      ((IItem) value).accept(visitor);
    } else if (value instanceof ISequence) {
      writeSequence((ISequence<?>) value);
    }
  }

  private final class Visitor implements IItemVisitor {

    @Override
    public void visit(IArrayItem<?> array) {
      writeArray(array);
    }

    @Override
    public void visit(IMapItem<?> map) {
      writeMap(map);
    }

    @Override
    public void visit(INodeItem node) {
      writeNode(node);
    }

    @Override
    public void visit(IAnyAtomicItem node) {
      writeAtomicValue(node);
    }

    @Override
    public void visit(IFunction function) {
      writeFunction(function);
    }
  }
}
